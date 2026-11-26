"""Unprivileged scheduling of root-admitted backup captures."""

from __future__ import annotations

import json
import math
import os
import sqlite3
import time
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .backupworker import Imports
from .core.backups import BackupError, regular_file
from .core.config import BackupEndpoint, Slug
from .executor.protocol import ExecutorError, call


class ScheduleConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: Literal[True]
    interval_s: int = Field(gt=0)
    max_mib: int = Field(gt=0)
    endpoint: BackupEndpoint
    config_revision: str = Field(pattern=r"^[a-f0-9]{64}$")
    projects: list[Slug] = Field(max_length=128)
    credentials: list[str] = Field(max_length=5)

    @field_validator("projects")
    @classmethod
    def distinct_projects(cls, projects):
        if len(set(projects)) != len(projects):
            raise ValueError("duplicate project")
        return projects


def read_config(path: Path, *, owner_uid: int = 0) -> ScheduleConfig:
    fd, info = regular_file(path, limit=65536)
    with os.fdopen(fd, "rb") as handle:
        if info.st_uid != owner_uid or info.st_mode & 0o022:
            raise BackupError("invalid_service_config")
        data = json.load(handle)
    return ScheduleConfig.model_validate(data)


class Scheduler:
    """Next-due values are hints; only the executor can admit another pause."""

    def __init__(
        self,
        config: ScheduleConfig,
        imports: Imports,
        state: Path,
        *,
        clock=time.time,
        request=call,
    ):
        self.config, self.imports, self.state = config, imports, state
        self.clock, self.request = clock, request
        with sqlite3.connect(state) as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS schedule_hints "
                "(project TEXT PRIMARY KEY, due REAL NOT NULL)"
            )
            db.execute(
                "DELETE FROM schedule_hints WHERE project NOT LIKE ?",
                (self.config.config_revision + ":%",),
            )

    def tick(self):
        results = {}
        for project in self.config.projects:
            now = self.clock()
            key = self.config.config_revision + ":" + project
            with sqlite3.connect(self.state) as db:
                row = db.execute(
                    "SELECT due FROM schedule_hints WHERE project=?", (key,)
                ).fetchone()
            if row and now < row[0]:
                continue
            try:
                result = self.request("backup_schedule", {"project_id": project}, timeout=60)
                upload = result.get("uploaded")
                artifact, capture = result["artifact"], result["capture_id"]
                path, manifest = self.imports.manifest(project, artifact)
                if (
                    result.get("project_id") != project
                    or upload is not False
                    or result.get("import_dir") != str(path)
                    or capture != manifest.id
                    or result.get("capture_created_at") != manifest.created_at
                    or result.get("config_revision") != manifest.binding.config_revision
                ):
                    raise BackupError("evidence_mismatch")
                due = float(result["next_capture_at"])
                if not math.isfinite(due) or due < 0:
                    raise BackupError("evidence_mismatch")
                results[project] = "scheduled"
            except ExecutorError as exc:
                due = now + 60
                results[project] = exc.error_class
            except (BackupError, ValueError, TypeError, KeyError, AttributeError, OSError):
                due = now + 60
                results[project] = "invalid_evidence"
            with sqlite3.connect(self.state) as db:
                db.execute("INSERT OR REPLACE INTO schedule_hints VALUES (?,?)", (key, due))
        return results
