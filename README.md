# Item Catalog

A Python module that uses a SQLite database to keep track of an item catalog organized in categories. It is multi-user and supports login with Google+. The creator of an item is the only one who can edit and delete it.

## How to use

The database is created by running the database_setup.py module, and it cand be populated with a user and a few items by running the populate_database.py module.

```
$ python database_setup.py
$ python populate_datase.py
```

Running the actual module is done by:
```
$ python application.py
```

The module is programmed to run on port 8000 and can be accessed at 
> [http://localhost:8000/](http://localhost:8000/)