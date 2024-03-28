# MindCanvas - A Journaling Flask Web App

MindCanvas is a simple web application developed by [Indrajit Ghosh](https://github.com/indrajit912) that allows you to journal your thoughts, ideas, and experiences. Built using Flask, this user-friendly application enables you to effortlessly create, view, update, and delete journal entries through an easy-to-use web interface.

- Website: [Demo on Render!](https://demo-mindcanvas.onrender.com) (Please note that this website may take some time to load!)
- Demo username: `demo`
- Demo password: `password`

![Homepage Screenshot](/app/static/images/homepage.png)
![ViewEntries Screenshot](/app/static/images/view_entries.png)

## Author

- **[Indrajit Ghosh](https://github.com/indrajit912)**
- **Email:** rs_math1902@isibang.ac.in

## Features

- **Create Entries**: Write and save your journal entries with titles, timestamps, and text content.
- **View Entries**: Browse through your previous journal entries with the ability to read, search, and filter.
- **Update Entries**: Edit and update your existing entries to reflect changes or add more details.
- **Delete Entries**: Remove entries you no longer need.
- **Download Data**: You have the option to retrieve the `json` file containing all the data stored on the server.
- **Data Security and Password Management**: All your data is securely encrypted with a password. The default credentials are username=admin and password=password. You have the flexibility to change the password at any time, but it is crucial to ensure you do not lose it. Without this password, you will be unable to access your data. This measure is in place to safeguard your data privacy. 

## Installation and Setup Guide

To get started with MindCanvas, follow these steps to download and run the provided installation script for your operating system. Make sure you have Python 3 and Git installed.

This guide will walk you through the process of installing and setting up MindCanvas, a Flask-based journaling app.

### Prerequisites

Before you begin, make sure you have the following prerequisites installed:

- Python 3.8 or higher
- pip (Python package manager)
- virtualenv (recommended for creating isolated environments)

### Installation

1. Open a terminal (or command prompt) window and clone the MindCanvas repository from GitHub:

   ```bash
   git clone https://github.com/indrajit912/MindCanvas.git
   ```

2. Navigate to the project directory:
    ```bash
    cd MindCanvas
    ```

3. Create a virtual environment (optional but recommended):
    ```bash
    python -m venv venv
    ```
4. Activate the virtual environment:
    - On Windows:
        ```bash
        venv\Scripts\activate
        ```
    - On macOS and Linux:
        ```bash
        source venv/bin/activate
        ```
5. Install the required dependencies using pip:
    ```bash
    pip install -r requirements.txt
    ```

### Running MindCanvas
Once you have installed the dependencies, you can run MindCanvas using the following command:
```bash
python3 run.py
```
MindCanvas should now be running locally on your machine. You can access it by opening a web browser and navigating to http://localhost:8080.

Enjoy using MindCanvas!


## Usage

- **Home Page**: Visit the home page to start your journaling journey.

- **View Entries**: Click on "View Entries" to see your existing journal entries.

- **Add New Entry**: Use the "Add New Entry" button to create a new journal entry.

- **Update Entry**: Click "Update" on an entry card to edit and update it.

- **Delete Entry**: Use the "Delete" button to remove an entry.

## Restricted API Endpoints

These are the restricted API endpoints. To make a request, a header with a private token is required. This token is meant for the admins only. A new set of APIs for the users of the app will be updated soon.


### User:

- **Get a Specific User:**
  - `GET /api/users/<int:user_id>`

- **Create New User:**
  - `POST /api/create/user/`

- **Update a Specific User:**
  - `PUT /api/users/<int:user_id>`

- **Delete a Specific User:**
  - `DELETE /api/users/<int:user_id>`

- **Get All Users:**
  - `GET /api/users`

- **Get User by Username:**
  - `GET /api/users/<string:username>`

- **Get User's journal entries on this day**
  - `GET /api/users/<string:username>/journal_entries?today=MM-DD`

- **Get All tags created by a specific User**
  - `GET /api/users/<string:username>/tags`

### Journal Entry:

- **Get a Specific Journal Entry:**
  - `GET /api/journal_entries/<int:journal_entry_id>`

- **Create New Journal Entry:**
  - `POST /api/create/journal_entry/`

- **Update a Specific Journal Entry:**
  - `PUT /api/journal_entries/<int:journal_entry_id>`

- **Delete a Specific Journal Entry:**
  - `DELETE /api/journal_entries/<int:journal_entry_id>`

- **Get All Journal Entries of a User:**
  - `GET /api/users/<int:user_id>/journal_entries`

### Tag:

- **Get a Specific Tag:**
  - `GET /api/tags/<int:tag_id>`

- **Create New Tag:**
  - `POST /api/create/tag/`

- **Update a Specific Tag:**
  - `PUT /api/tags/<int:tag_id>`

- **Delete a Specific Tag:**
  - `DELETE /api/tags/<int:tag_id>`

- **Get All Tags:**
  - `GET /api/tags`



## Contributing

If you'd like to contribute to MindCanvas, feel free to open a pull request or submit issues on the [GitHub repository](https://github.com/indrajit912/MindCanvas). Your contributions are welcome!

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.