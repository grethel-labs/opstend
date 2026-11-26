"""Normalize content identities without equating different manifest digests."""

import re


def image_id(value):
    if not isinstance(value, str):
        return None
    raw = value.removeprefix("sha256:")
    return "sha256:" + raw if re.fullmatch(r"[a-f0-9]{64}", raw) else None


def configured_content_id(observation):
    expected = observation["configured_image"].rsplit("@", 1)[-1]
    # This mapping is supplied by the root executor after inspecting its own
    # pinned-reference cache, never learned from rootless tags or image labels.
    trusted = observation.get("configured_image_identity") or {}
    if not isinstance(trusted, dict):
        trusted = {}
    identity = image_id(trusted.get("id"))
    if identity and trusted.get("manifest_digest") == expected:
        return identity
    if observation.get("observed_image_digest") == expected:
        return image_id(observation.get("observed_image_id"))
    return None


def runtime_identity_verified(observation):
    if not observation.get("observed") or observation.get("observed_running") is not True:
        return False
    expected = configured_content_id(observation)
    return bool(expected) and expected == image_id(observation.get("observed_image_id"))
