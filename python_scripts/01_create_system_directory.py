import os

def main():
    directory = "secure_logs"
    if not os.path.exists(directory):
        os.makedirs(directory)
        print(f"Success: Directory '{directory}' created.")
    else:
        print(f"Directory '{directory}' already exists.")

if __name__ == "__main__":
    main()
