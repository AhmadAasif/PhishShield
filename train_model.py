from detector import train_model

if __name__ == "__main__":
    count = train_model(force=True)
    print(f"PhishShield model trained successfully using {count} labelled URL examples.")
    print("Saved model: model/phishshield_model.joblib")
