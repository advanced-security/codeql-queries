import os
import pickle

# > Local input
i = input()

pickle.loads(i)

# > Local Environment Variables
e = pickle.dumps(os.environ.get('LOCAL_DATA'))

pickle.loads(e)


# > Files
with open('data.txt', 'rb') as f:
    d = pickle.loads(f.read())
