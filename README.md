# Xen/Infoblox Shell Tool, WIP
## Overview

Allows to find a virtual machine through the range of independent xen hypervisors.
Hypervisors addressing scheme supported: hypX.podY.DC.domain.com

- Find virtual machine: `xensh findvm vmX.podY.DC.domain.com`
- Destroy virtual machine: `xensh remove vmX.podY.DC.domain.com hypX.podY.DC.domain.com`
- Find and Destroy virtual machine: `xensh searchdel vmX.podY.DC.domain.com`
- Remove fixed address record object and host record object from Infoblox grid 
`xensh delhost vmX.podY.DC.domain.com`

Flag `DRY=false` will make actual changes, withtout environment variable set tool wouldn't perform actual change

We are using goroutine() to achieve concurrency, finding machine should be really fast (3 seconds for 20 hypervisors).

Range of hypervisors from 1 to 20.

## Install

Use go get:
````
go get github.com/murat1985/xensh
````
package would be installed into your $GOBIN path, e.g.: 
```
/usr/local/go/bin
```

## Configuration 
Configuration would be automatically generated on first run and stored at
```
~/.xensh.json
```
Password is store as clear text

Another password is ~/.infoblox.json - not being created automatically for security concerns


## TODO

1. Create a machine
2. Suspend machine and create the machine with the same label and mac, without destroying old one
