# test_compatibility.py
import subprocess
import sys


def test_install(protobuf_version, grpcio_version):
    try:
        subprocess.run([sys.executable, "-m", "pip", "install",
                        f"protobuf=={protobuf_version}",
                        f"grpcio-tools=={grpcio_version}",
                        "etcd3>=0.12.0"],
                       check=True, capture_output=True)

        # Test imports
        import google.protobuf
        import etcd3
        import grpc_tools

        print(f"SUCCESS: protobuf={protobuf_version}, grpcio-tools={grpcio_version}")
        return True
    except:
        print(f"FAIL: protobuf={protobuf_version}, grpcio-tools={grpcio_version}")
        return False


# Test combinations
combinations = [
    ("3.20.3", "1.48.0"),
    ("3.20.3", "1.44.0"),
    ("3.19.0", "1.44.0"),
    ("4.21.0", "1.57.0"),  # con variable de entorno
]

for proto_ver, grpc_ver in combinations:
    test_install(proto_ver, grpc_ver)