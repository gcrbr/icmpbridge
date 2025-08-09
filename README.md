# icmpbridge
An ICMP bridge with its own messaging system that can be used to forward packets to other applications through TCP or UDP.

**Disclaimer**: This project is still work in progress and was developed for fun and not for any particular real-world use.

## Usage
Forwarding rules are stored in the `rules.yml`file.

You can use the `./build`script to build the executable and then run it as follows:
```bash
./icmpbridge [-i interface] [-p password] [-r rules file]
```

## Examples
You can run an HTTP proxy over ICMP, check the example in the `client/examples`folder:
1. Run the bridge on a remote host (make sure it does not answer to ICMP echo requests): 
    ```bash
    ./icmpbridge -p yourpassword
    ``` 
2. Run any HTTP proxy software on the remote host on the port 8080 (you can change it from the rules file)
3. Run the proxy server on your machine: 
    ```bash
    python3 proxy.py -r remotehost -pw yourpassword
    ```
4. Try it out:
    ```bash
    curl 'http://example.com' -x 'http://127.0.0.1:8080'
    ```
