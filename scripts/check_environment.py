"""Optional dependency/version check; not part of the pytest suite."""

import sys

import fastapi
import numpy
import pandas
import sklearn


def main() -> None:
    print("Python:", sys.version)
    print("Pandas:", pandas.__version__)
    print("NumPy:", numpy.__version__)
    print("Scikit-learn:", sklearn.__version__)
    print("FastAPI:", fastapi.__version__)
    print("Environment setup completed successfully.")


if __name__ == "__main__":
    main()
