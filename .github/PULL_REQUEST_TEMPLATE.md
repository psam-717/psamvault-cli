name: Pull Request
description: Submit changes to psamvault
labels: []

body:
  - type: markdown
    attributes:
      value: |
        Thanks for contributing! Please make sure you've read [CONTRIBUTING.md](https://github.com/psam-717/psamvault-cli/blob/main/CONTRIBUTING.md) first.

  - type: dropdown
    id: type
    attributes:
      label: Type of change
      options:
        - 🐛 Bug fix
        - ✨ New feature
        - 📝 Documentation
        - ♻️ Refactor
        - 🔧 Chore (deps, config, CI)
    validations:
      required: true

  - type: textarea
    id: description
    attributes:
      label: Description
      description: What does this PR do and why?
      placeholder: "This PR adds ... because ..."
    validations:
      required: true

  - type: textarea
    id: testing
    attributes:
      label: How was this tested?
      description: Describe the tests you ran or ran manually.
      placeholder: "Ran pytest tests/ -v, verified with psamvault get ..."

  - type: checkboxes
    id: checks
    attributes:
      label: Checklist
      options:
        - label: I have read the CONTRIBUTING.md guide
          required: true
        - label: My changes follow the existing code style
        - label: I have added tests for my changes (if applicable)
        - label: I have updated the documentation (if applicable)
