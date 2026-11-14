[devdoctor]
enabled      = true
backend      = systemd
journalmatch = _SYSTEMD_UNIT=devdoctor.service
filter       = devdoctor
port         = __PORT__
maxretry     = 5
findtime     = 10m
bantime      = 1h
