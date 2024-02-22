# Site Generation Tool

## Installing 
Requires [poetry](https://python-poetry.org/docs/)

```
git clone https://github.com/splunk/security_content.git
git clone https://github.com/mitre/cti.git
poetry install && poetry shell
```

# Development
To run a local jekyll install follow these steps:

1. Install Gems with bundler `bundler install`
2. You might want to generate a fresh site: `python bin/site_gen.py`
3. Run jekyll `bundle exec jekyll serve`

Current Version: v4.25.0
