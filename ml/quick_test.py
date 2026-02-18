from infer import NorthStarTFIDFModels

m = NorthStarTFIDFModels()

tests = [
  "dumping telecom database creds tonight",
  "private key exposed -----BEGIN RSA PRIVATE KEY-----",
  "selling access to airport systems dm for creds",
  "football match tonight was great"
]

for t in tests:
  print("\nTEXT:", t)
  print("INTENT:", m.predict_intent(t))
  print("SECTORS:", m.predict_sectors(t))

