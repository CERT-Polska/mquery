# remove_datasets.py

Remove unneccesary dataset files in the index directory.
It doing that by checking the IDs of all files in the directory,
and validating if they exist in "db.ursa" file.

## Usage
Update the "index_basepath" variable:
`index_basepath = "/mnt/index/"`

Run the script without arguments:

```
$ python3 utils/remove_datasets.py
```

## Example

```
$ python3 utils/remove_datasets.py
INFO:root:Removing hash4.set.bfd8cc44.db.ursa
...
```
