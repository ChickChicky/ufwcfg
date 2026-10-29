# UFW easy Configuration

Very simple config file for basic UFW commands.

# Usage

```shell
# python3 main.py <config file>
```

# Example

```ini
[rules]
# allow all traffic on lo/eth0
  lo
    <> allow
  eth0
    <> allow

# restrict to only port 80 for ygg0
  ygg0:
#  allow all outbound traffic
    -> y
#  allow all traffic to local port 80
    <- y <:80
#  rejecct all other inbound traffic
    <- n

# Interface format:
#
# interface name
#   rule 1
#   rule 2
#   ...

# Rule:
#
#   <direction> <action> <filter[]>
#
# example: <- allow <:8080 >10.0.0.2
#          (allow 10.0.0.2 to access local port 8080)
#          -> deny <10.0.0.2:80
#          (deny access from this machine to 10.0.0.2:80)

# Direction:
#
#   both: <> / <.> / <-> / <=>
#   in:   <  / <.  / <-  / <=
#   out:   > /  .> /  -> /  =>

# Action:
#
#   allow: a / allow / y / yes / v / ok
#   deny:  d / deny  / n / no  / x / nope

# Filter:
#   
#   <direction>[host][:port]
#
# example: <:80
#          (matches traffic to local port 80)
#          >:80
#          (matches traffic from remote port 80)
#          <10.0.0.3:80
#          (matches traffic to 10.0.0.3 on port 80)
#          >10.0.0.3:80
#          (matches traffic from 10.0.0.3 on remote port 80)
```

