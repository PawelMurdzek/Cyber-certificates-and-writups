# OSINT (Open-Source Intelligence) Cheatsheet

A collection of tools and techniques for gathering information from publicly available sources.

## Username & Nickname Search

Tools for finding user profiles across multiple social networks and websites based on a single username.

### Sherlock
- **Description:** One of the most famous username search tools. It's written in Python, runs from the command line, and checks a database of several hundred websites.
- **Repository:** [sherlock-project/sherlock](https://github.com/sherlock-project/sherlock)
- **Usage:**
  ```bash
  # Clone the repository first
  git clone https://github.com/sherlock-project/sherlock.git
  cd sherlock
  # Install dependencies
  python -m pip install -r requirements.txt
  # Run the search
  python sherlock.py <username>
  ```

### Maigret
- **Description:** An advanced fork (descendant) of Sherlock, often providing even more accurate results and additional features.
- **Repository:** [soxoj/maigret](https://github.com/soxoj/maigret)
- **Usage:**
  ```bash
  # Install with pip
  pip install maigret
  # Run the search
  maigret <username>
  ```

### WhatsMyName.app
- **Description:** A web service that performs a username search across many sites. You enter a nickname and get a categorized list of links.
- **Website:** [whatsmyname.app](https://whatsmyname.app/)

### Namechk
- **Description:** A more commercially-oriented tool that also checks for domain name availability, but its username search function operates on the same principle.
- **Website:** [namechk.com](https://namechk.com/)
