"""Permit async tests in minimal offline environments without pytest-asyncio."""

import asyncio
import importlib.util
import inspect
import pytest

if importlib.util.find_spec("pytest_asyncio") is None:

    @pytest.hookimpl(tryfirst=True)
    def pytest_pyfunc_call(pyfuncitem):
        if inspect.iscoroutinefunction(pyfuncitem.obj):
            args = {name: pyfuncitem.funcargs[name] for name in pyfuncitem._fixtureinfo.argnames}
            asyncio.run(pyfuncitem.obj(**args))
            return True
        return None
