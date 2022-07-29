# Mini container built in C++

## Preparation

Create folder "root":

```mkdir root && cd root```

Download alpine minirootfs inside the root folder:

```curl -Ol http://nl.alpinelinux.org/alpine/v3.7/releases/x86_64/alpine-minirootfs-3.7.0-x86_64.tar.gz```

``` tar -xvf alpine-minirootfs-3.7.0-x86_64.tar.gz```

After you extract this minirootfs, run:
```make```

Finally, execute program:
```./main``` (No root this time!)