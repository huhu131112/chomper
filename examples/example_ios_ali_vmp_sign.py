import logging
import os
import urllib.request
import uuid
from pathlib import Path

from chomper import Chomper
from chomper.const import ARCH_ARM64, OS_IOS
from chomper.objc import ObjC
from chomper.utils import pyobj2nsobj

base_path = os.path.abspath(os.path.dirname(__file__))

log_format = "%(asctime)s - %(name)s - %(levelname)s: %(message)s"
logging.basicConfig(
    format=log_format,
    level=logging.INFO,
)

logger = logging.getLogger(__name__)


def hook_skip(uc, address, size, user_data):
    pass


def hook_retval(retval):
    def decorator(uc, address, size, user_data):
        return retval

    return decorator


def hook_ns_bundle(emu):
    executable_path = f"/var/containers/Bundle/Application/{uuid.uuid4()}/com.ceair.b2m/ceair_iOS_branch"

    bundle_info = {
        "CFBundleShortVersionString": "9.4.7",
        "CFBundleExecutable": executable_path,
    }

    emu.add_interceptor("-[NSBundle initWithPath:]", hook_skip)
    emu.add_interceptor("-[NSBundle bundleIdentifier]", hook_retval(pyobj2nsobj(emu, "com.ceair.b2m")))
    emu.add_interceptor("-[NSBundle executablePath]", hook_retval(pyobj2nsobj(emu, executable_path)))
    emu.add_interceptor("-[NSBundle infoDictionary]", hook_retval(pyobj2nsobj(emu, bundle_info)))


def retrieve_binary(url: str, filepath: str):
    path = Path(filepath)
    if path.exists():
        return
    if not path.parent.exists():
        path.parent.mkdir(parents=True)
    print(f"Retrieving binary: {url}")
    urllib.request.urlretrieve(url, path)


def main():
    # Download example binary file from the Internet
    binary_path = "binaries/ios/com.csair.MBP/CSMBP-AppStore-Package"
    retrieve_binary(
        url=f"https://sourceforge.net/projects/chomper-emu/files/examples/{binary_path}/download",
        filepath=os.path.join(base_path, binary_path),
    )

    emu = Chomper(
        arch=ARCH_ARM64,
        os_type=OS_IOS,
        rootfs_path=os.path.join(base_path, "rootfs/ios"),
        enable_ui_kit=True,
    )

    objc = ObjC(emu)

    hook_ns_bundle(emu)

    emu.load_module(os.path.join(base_path, binary_path))

    ali_tiger_tally_instance = objc.msg_send("AliTigerTally", "sharedInstance")

    app_key = "xPEj7uv0KuziQnXUyPIBNUjnDvvHuW09VOYFuLYBcY-jV6fgqmfy5B1y75_iSuRM5U2zNq7MRoR9N1F-UthTEgv-QBWk68gr95BrAySzWuDzt08FrkeBZWQCGyZ0iAybalYLOJEF7nkKBtmDGLewcw=="
    objc.msg_send(ali_tiger_tally_instance, "initialize:", pyobj2nsobj(emu, app_key))

    with objc.autorelease_pool():
        encrypt_str = '{"biClassId":["2","3","4"]}'
        encrypt_bytes = objc.msg_send(pyobj2nsobj(emu, encrypt_str), "dataUsingEncoding:", 1)

        vmp_sign = objc.msg_send(ali_tiger_tally_instance, "vmpSign:", encrypt_bytes)
        logger.info("vmpSign: %s", emu.read_string(objc.msg_send(vmp_sign, "cStringUsingEncoding:", 4)))


if __name__ == "__main__":
    main()
