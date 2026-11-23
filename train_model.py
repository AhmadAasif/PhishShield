"""Compatibility trainer. Add --download-dataset to refresh public feeds before evaluation."""
import subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
if __name__=="__main__":
 if "--download-dataset" in sys.argv:subprocess.check_call([sys.executable,str(ROOT/"dataset_builder.py")])
 subprocess.check_call([sys.executable,str(ROOT/"train_models.py")])
