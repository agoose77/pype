from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric.dh import DHPublicKey, DHPrivateKey


def read_only_property(name):
    @property
    def get_prop(self):
        return getattr(self, name)

    return get_prop


class DHSecretMediator:

    def __init__(self, p, g, a):
        self._p = p
        self._g = g
        self._a = a

    p = read_only_property("_p")
    g = read_only_property("_g")

    def compute_result(self):
        return (self._g ** self._a) % self._p

    def get_shared_number(self, n):
        return (n ** self._a) % self._p


class DHPeer:

    def __init__(self, a):
        self._a = a

    def create_mediator(self, p, g):
        return DHSecretMediator(p, g, self._a)


p1 = DHPeer(7927)
p2 = DHPeer(8831)

m1 = p1.create_mediator(15486071, 32416190039)
m2 = p2.create_mediator(m1.p, m1.g)

print("Mediated")

c1 = m1.compute_result()
c2 = m2.compute_result()

print("COMPUTED")
secret1 = m1.get_shared_number(c2)
secret2 = m2.get_shared_number(c1)

print(secret1, secret2)
