import xxhash
import pickle
import time
import logging

class IpRecord():
    def __init__(
            self,
            address = '0.0.0.0',
            path = '/',
            method = 'GET',

            response_code = 200,

            headers = {},

            timestamp = time.time(),
            hashed = False,
            track_headers = False
        ):
        self.address = address
        self.path = path
        self.method = method

        self.response_code = response_code

        self.track_headers = track_headers

        self.headers = {}
        #self.body = b''

        if track_headers:
            self.headers = dict(headers)
            #self.body = body

        self.timestamp = timestamp

        self.hashed_address = ''
        self.hashed = hashed
        self.already_hashed = False

        if self.hashed and not self.already_hashed:
            self.encrypt()
            self.already_hashed = True

    def __repr__(self):
        address = self.address
        if self.hashed:
            address = f"HASHED {self.hashed_address}"
        return f"[{address}] [{self.method} {self.path}] -> [{self.response_code}] [{self.timestamp}]"
    
    def encrypt(self):
        hash_function = xxhash.xxh3_64()
        hash_function.update(self.address.encode())
        self.hashed_address = hash_function.hexdigest()
        self.address = ''

        if self.track_headers:
            for key,value in self.headers.items():
                hash_function = xxhash.xxh3_64()
                hash_function.update(value.encode())
                self.headers[key] = hash_function.hexdigest()

    def serialize(self):
        return pickle.dumps(self)

    def deserialize(record_bytes):
        return pickle.loads(record_bytes)

class IpBase():
    def __init__(self):
        self.records = []
        self.ips = {}
        self.store_every_unit = 10
        self.store_index = 1
        self.file_path = "ip_base.pikle"

        logging.getLogger("werkzeug").disabled = True
        logging.basicConfig(filename='ip.log', encoding='utf-8', level=logging.DEBUG)
        self.logger = logging.getLogger("IpTracker")

    def append(self,record:IpRecord):
        self.logger.info(record)
        self.records.append(record)

        address = record.address
        if record.hashed:
            address = record.hashed_address
        
        if self.ips.get(address) is None:
            self.ips[address] = 0
        
        self.ips[address] += 1

        self.store_index += 1

        if self.store_index == self.store_every_unit:
            with open(self.file_path,"wb") as f:
                f.write(self.serialize())
            self.store_index = 0

    def serialize(self):
        return pickle.dumps(self)

    def deserialize(base_bytes):
        return pickle.loads(base_bytes)

if __name__ == "__main__":
    base = IpBase.deserialize(
        open("ip_base.pikle","rb").read()
    )

    print(base.records[0].headers)
    print(base.ips)