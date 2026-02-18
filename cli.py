import getpass
from password_checker import score_password

password = getpass.getpass("Enter password to evaluate: ")
result = score_password(password)

print("\nPassword Analysis:")
print(f"Strength: {result['strength']}")
print(f"Entropy: {result['entropy']} bits")

for reason in result["reasons"]:
    print(f"- {reason}")
