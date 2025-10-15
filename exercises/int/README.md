# Topo

```
h1 - s1 - s2 - s3 - h2 
                |
                h3
```


# Run

```
$ make clean && make run
mininet> xterm h1
mininet> h3 ./report.py
```
In xterm,
```
$ ./send.py 10.0.3.3. "Hello!"