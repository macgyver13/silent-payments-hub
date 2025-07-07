# [Setup](https://github.com/SeedSigner/seedsigner)


```
cd seedsigner
pip install -r requirements.txt
pip install -r tests/requirements.txt
pip install -e .
```

**[reference](https://github.com/SeedSigner/seedsigner/blob/dev/tests/README.md)

# Testing

Date: 2025-06-24 [PR #769](https://github.com/SeedSigner/seedsigner/pull/769)

#### Evaluate BIP 352 test vectors
```
pytest tests/test_embit_utils.py
```