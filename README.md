# UserAuth

## Create DB
Run `python .\main.py` to create and populate example database.

## Setup
`python -m venv .venv` 
`.\\.venv\\Scripts\\Activate.ps1`
`pip install -r requirements.txt`
`$env:FLASK_SECRET_KEY=your_key`
`$env:GOOGLE_CLIENT_ID=your_client_id`
`$env:GOOGLE_CLIENT_SECRET=your_client_secret`
Client info not listed in repository as it should not be publicly available, contact us if needed.

## Ready to run
`python app.py` To start webapp, terminal shows local ip address.


## BCRYPT_ROUNDS
Can be changed in `app.py` and `db.py`.