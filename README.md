# MindCanvas

MindCanvas is a Flask-based journaling app designed to securely document users' thoughts, daily events, and more. With end-to-end encryption and user-centric features, it prioritizes privacy and usability.

## Features

1. **Secure Password Handling**: User passwords are securely hashed and never stored in plaintext.
2. **End-to-End Encryption**: Journal entries are encrypted using a private key derived from the user's password, ensuring confidentiality.
3. **Tagging System**: Users can organize their entries with tags for easy retrieval.
4. **Search Functionality**: Users can search their journal entries by keywords or tags.
5. **Data Portability**: Users can export/import all their data for backup or migration.
6. **LaTeX Support**: Write mathematical equations using LaTeX typesetting directly into your Journal Entries.
7. **Demo Account**: A demo account (username: demo, password: password) allows users to explore the app before creating their own accounts.

## Installation

1. Clone the repository:

```bash
git clone https://github.com/indrajit912/MindCanvas.git
```

2. Create a virtualenv
```bash
virtualenv env
source env/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up the database:
```bash
python managa.py setup-db
```

5. Run the app:
```bash
python run.py
```

The app will be up at `http://localhost:8080`

## Usage
- Register for an account or use the demo account credentials provided.
- Start journaling! Add entries, tag them, and search whenever needed.
- Enjoy the peace of mind knowing your thoughts are securely encrypted.

## License
This project is licensed under the [MIT License](./LICENSE), which allows users to use, modify, and distribute the software with minimal restrictions.

## Author
[Indrajit Ghosh](https://indrajitghosh.onrender.com) (Senior Research Fellow, Stat-Math Unit, Indian Statistical Institute Bangalore)
