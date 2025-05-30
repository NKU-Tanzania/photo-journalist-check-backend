# Photo Journalist Check Backend

This repository provides the backend for verifying photos in the context of photojournalism. The project ensures that photos submitted by citizen journalists are authentic and meet verification standards, supporting integrity in news reporting.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Getting Started](#getting-started)
- [API Documentation](#api-documentation)
- [Contributing](#contributing)
- [License](#license)

## Overview

Photo Journalist Check Backend is designed to help organizations and newsrooms verify the authenticity of photos submitted by photojournalists. The platform streamlines the review and validation process, supporting a trustworthy workflow for image-based reporting.

## Features

- User authentication and management
- Photo upload and verification workflows
- admin photo verification
- RESTful API endpoints for integration with frontend
- Admin controls

## Tech Stack

- **Backend Framework:** Django (Python)
- **Frontend Assets:** HTML, CSS, kotlin (for admin interface or static content)
- **Database:** PostgreSQL

## Getting Started

### Prerequisites

- Python 3.8+
- django
- pip
- virtualenv (Recommended)
- Database server, PostgreSQL

### Installation

```bash
# Clone the repository
git clone https://github.com/NKU-Tanzania/photo-journalist-check-backend.git
cd photo-journalist-check-backend

# Create a virtual environment and activate it
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Apply migrations
python manage.py makemigrations
python manage.py migrate

# Create a superuser for admin access
python manage.py createsuperuser

# Start the development server
python manage.py runserver
```

### Environment Variables

Create a `.env` file in the root directory and configure the following variables:

```
SECRET_KEY=your_django_secret_key
DEBUG=True
DATABASE_URL=your_database_url
ALLOWED_HOSTS=localhost,127.0.0.1
```


## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/YourFeature`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature/YourFeature`)
5. Open a Pull Request

## License

Distributed under the GNU License. See `LICENSE` for more information.
[GNU](LICENSE)
