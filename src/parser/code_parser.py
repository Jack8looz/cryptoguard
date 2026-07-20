import os
import re
from dataclasses import dataclass
from typing import List, Optional
import tree_sitter_java
import tree_sitter_kotlin
from tree_sitter import Language, Parser

JAVA   = Language(tree_sitter_java.language())
KOTLIN = Language(tree_sitter_kotlin.language())

CRYPTO_IMPORTS = [
    "javax.crypto", "java.security", "javax.net.ssl",
    "org.bouncycastle", "android.security.keystore",
    "java.security.spec", "javax.crypto.spec",
    "io.jsonwebtoken", "com.auth0.jwt", "java.sql",
    "javax.security.auth.kerberos",
]

CRYPTO_KEYWORDS = [
    "Cipher", "MessageDigest", "KeyGenerator", "KeyPairGenerator",
    "SecretKeySpec", "IvParameterSpec", "SecureRandom", "Random",
    "Mac", "Signature", "KeyStore", "TrustManager", "SSLContext",
    "BCrypt", "Argon2", "PBKDF2", "PBEKeySpec", "SecretKeyFactory",
    "JWT", "JwtParser", "Algorithm", "parseClaimsJws", "parseClaimsJwt",
    "SharedPreferences", "AES", "DES", "RSA", "ECB", "CBC", "GCM",
    "MD5", "SHA-1", "SHA1", "SHA-256", "SHA256", "HMAC",
    "DriverManager", "getConnection", "Math.random",
    "KerberosKey", "KerberosPrincipal", "KerberosTicket",
    "HostnameVerifier", "hostnameVerifier", "onReceivedSslError", "CertificatePinner",
    "cvv", "CVV", "cvc2", "CVC2", "pinBlock", "PIN_BLOCK", "trackData", "track2Data",
    "SCrypt", "gensalt",
    "DexClassLoader", "PathClassLoader", "PackageInstaller", "firmwareUpdate",
    "bootloader", "promptRenderer", "promptFile", "checksum", "Checksum",
]

@dataclass
class CodeSnippet:
    file_path:    str
    language:     str
    method_name:  str
    start_line:   int
    end_line:     int
    code:         str
    context:      str  # class name if available


def _is_crypto_relevant(code: str) -> bool:
    for kw in CRYPTO_KEYWORDS:
        if kw in code:
            return True
    return False


def _has_crypto_import(source: str) -> bool:
    for imp in CRYPTO_IMPORTS:
        if imp in source:
            return True
    return False


def _get_node_text(node, source_bytes: bytes) -> str:
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")


def _extract_methods_java(source: str) -> List[CodeSnippet]:
    snippets = []
    source_bytes = source.encode("utf-8")
    parser = Parser(JAVA)
    tree = parser.parse(source_bytes)

    def find_class_name(node) -> Optional[str]:
        for child in node.children:
            if child.type == "class_declaration":
                for c in child.children:
                    if c.type == "identifier":
                        return _get_node_text(c, source_bytes)
            result = find_class_name(child)
            if result:
                return result
        return None

    class_name = find_class_name(tree.root_node) or "Unknown"

    def walk(node, depth=0):
        if node.type in ("method_declaration", "constructor_declaration"):
            code = _get_node_text(node, source_bytes)
            if _is_crypto_relevant(code):
                method_name = "unknown"
                for child in node.children:
                    if child.type == "identifier":
                        method_name = _get_node_text(child, source_bytes)
                        break
                snippets.append(CodeSnippet(
                    file_path="",
                    language="java",
                    method_name=method_name,
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                    code=code,
                    context=class_name,
                ))
        for child in node.children:
            walk(child, depth + 1)

    walk(tree.root_node)
    return snippets


def _extract_methods_kotlin(source: str) -> List[CodeSnippet]:
    snippets = []
    source_bytes = source.encode("utf-8")
    parser = Parser(KOTLIN)
    tree = parser.parse(source_bytes)

    def find_class_name(node) -> Optional[str]:
        for child in node.children:
            if child.type == "class_declaration":
                for c in child.children:
                    if c.type == "type_identifier":
                        return _get_node_text(c, source_bytes)
            result = find_class_name(child)
            if result:
                return result
        return None

    class_name = find_class_name(tree.root_node) or "Unknown"

    def walk(node):
        if node.type in ("function_declaration", "anonymous_function"):
            code = _get_node_text(node, source_bytes)
            if _is_crypto_relevant(code):
                method_name = "unknown"
                for child in node.children:
                    if child.type == "simple_identifier":
                        method_name = _get_node_text(child, source_bytes)
                        break
                snippets.append(CodeSnippet(
                    file_path="",
                    language="kotlin",
                    method_name=method_name,
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                    code=code,
                    context=class_name,
                ))
        for child in node.children:
            walk(child)

    walk(tree.root_node)
    return snippets


def extract_snippets_from_file(file_path: str) -> List[CodeSnippet]:
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()
    except Exception as e:
        print(f"  [WARN] Cannot read {file_path}: {e}")
        return []

    if not _has_crypto_import(source) and not _is_crypto_relevant(source):
        return []

    ext = os.path.splitext(file_path)[1].lower()
    if ext == ".java":
        snippets = _extract_methods_java(source)
    elif ext == ".kt":
        snippets = _extract_methods_kotlin(source)
    else:
        return []

    for s in snippets:
        s.file_path = file_path

    return snippets


def extract_snippets_from_dir(dir_path: str) -> List[CodeSnippet]:
    all_snippets = []
    for root, _, files in os.walk(dir_path):
        for fname in files:
            if fname.endswith((".java", ".kt")):
                path = os.path.join(root, fname)
                snippets = extract_snippets_from_file(path)
                if snippets:
                    print(f"  [PARSE] {path} — {len(snippets)} snippet(s)")
                all_snippets.extend(snippets)
    return all_snippets


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    if os.path.isfile(target):
        snips = extract_snippets_from_file(target)
    else:
        snips = extract_snippets_from_dir(target)

    print(f"\nTotal snippets extracted: {len(snips)}")
    for s in snips[:3]:
        print(f"\n--- {s.file_path}:{s.start_line} [{s.language}] {s.context}.{s.method_name} ---")
        print(s.code[:300])