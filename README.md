# IOKitLibAnalysis

How to run:

macOS:
```
sudo frida bluetoothd --no-pause -l IOKit.js
sudo frida coreaudiod --no-pause -l IOKit.js
```

iOS:
```
frida -U bluetoothd --no-pause -l IOKit.js
frida -U wifid --no-pause -l IOKit.js
```
etc.
