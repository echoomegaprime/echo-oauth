# Contributing

Add a failing test for every behavior change. Run `python -m pytest -q` and `python -m compileall -q src app.py` before opening a pull request. Treat callback, state, scope, and credential-handling changes as security-sensitive. Test only with synthetic codes and tokens.
