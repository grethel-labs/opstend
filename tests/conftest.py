import pytest

from opstend import i18n


@pytest.fixture(autouse=True)
def english():
    token = i18n.current.set("en")
    yield
    i18n.current.reset(token)
