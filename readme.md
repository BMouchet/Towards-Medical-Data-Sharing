# Master Thesis Proof of concept
Benjamin Mouchet, year 2024-2025
## Quick start guide
1. Install WolfSSl as shown [here](https://www.wolfssl.com/docs/quickstart/)
2. Self signed certificates are already available. If they expired generate new ones as shown [here](https://mariadb.com/docs/server/security/data-in-transit-encryption/create-self-signed-certificates-keys-openssl/)
3. Install the requirements `pip install -r requirements.txt` (venv recommended)
4. Run the `docker-compose.yml` to start the MongoDB image with `docker compose up`
5. Run the `src/tests/populate_db.py` file to populate the data. (The entries value can be reduced if you want than a million documents)
5. You then can run the `[simple|extended] data access` main files to test the interactions between the clients or the same folders in the `tests` folder if you want to generate your data.
6. A Jupyter Notebook with the results is available in the `tests` folder

_These steps where tested on a Ubuntu WSL on Windows 11_ 
