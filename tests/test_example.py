from pathlib import Path


def test_readme_contains_identical_example():
    source = Path("examples/fastapi_app/app.py").read_text()
    assert "```python\n" + source + "```" in Path("README.md").read_text()
