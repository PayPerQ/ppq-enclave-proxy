#!/usr/bin/env python3
"""Unit tests for the measured-path logic in check-drift.py.

Run from the repo root: `python3 -m unittest scripts/test_check_drift.py`.
Stdlib only, like the script. The rest of check-drift.py talks to AWS, the
enclave and GitHub and is exercised by the scheduled workflow, not here.

The gap these pin down (Oct 17-19 security reports, Keyzo): MEASURED listed
five paths while the Dockerfile measured four more, so a change to
enclave/attest/, enclave/kmstool/ or scripts/build-enclave.sh shipped a new
PCR0 that step 3 of the check would never have flagged.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)


def load():
    spec = importlib.util.spec_from_file_location(
        "check_drift", os.path.join(HERE, "check-drift.py")
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


cd = load()

# The list the script carried before the fix, for the regression assertions.
OLD_MEASURED = (
    "enclave/src/",
    "enclave/boot.sh",
    "enclave/Dockerfile",
    "enclave/package.json",
    "enclave/package-lock.json",
)

# The four paths Keyzo's report named, each of which moves PCR0.
REPORTED_GAPS = (
    "enclave/attest/attest.go",
    "enclave/attest/go.mod",
    "enclave/kmstool/nsm-api-v0.4.0.Cargo.lock",
    "scripts/build-enclave.sh",
)


class IsMeasured(unittest.TestCase):
    def test_reported_gaps_are_now_measured(self):
        for path in REPORTED_GAPS:
            with self.subTest(path=path):
                self.assertFalse(cd.is_measured(path, OLD_MEASURED), "was not a gap?")
                self.assertTrue(cd.is_measured(path))

    def test_directory_entries_match_as_prefixes(self):
        self.assertTrue(cd.is_measured("enclave/src/server.mjs"))
        self.assertTrue(cd.is_measured("enclave/src/deep/er/file.mjs"))
        self.assertTrue(cd.is_measured("enclave/attest/go.sum"))

    def test_file_entries_match_exactly(self):
        self.assertTrue(cd.is_measured("enclave/boot.sh"))
        self.assertTrue(cd.is_measured("enclave/.dockerignore"))
        # The old `startswith` matched any path that merely began with a file
        # entry's name; a sibling like Dockerfile.bak is not measured.
        self.assertFalse(cd.is_measured("enclave/Dockerfile.bak"))
        self.assertFalse(cd.is_measured("enclave/boot.sh.orig"))

    def test_unmeasured_paths(self):
        for path in ("README.md", "enclave/test/x.test.mjs", "scripts/check-drift.py",
                     "attestation/published-pcr.json", ".github/workflows/enclave-build.yml"):
            with self.subTest(path=path):
                self.assertFalse(cd.is_measured(path))


class DockerfileCopySources(unittest.TestCase):
    def test_parses_context_copies_and_skips_stage_copies(self):
        text = """
FROM golang@sha256:abc AS attestbuilder
WORKDIR /attest
COPY attest/go.mod attest/go.sum ./
COPY attest/ ./
FROM node:22@sha256:def
COPY --chown=node:node package.json package-lock.json /app/
COPY ./src/ /app/src/
ADD boot.sh /app/boot.sh
COPY --from=attestbuilder /attest /app/attest
COPY --from=kmstoolbuilder --chmod=755 /usr/bin/kmstool_enclave_cli /usr/bin/kmstool_enclave_cli
"""
        self.assertEqual(
            cd.dockerfile_copy_sources(text),
            [
                "enclave/attest/go.mod",
                "enclave/attest/go.sum",
                "enclave/attest/",
                "enclave/package.json",
                "enclave/package-lock.json",
                "enclave/src/",
                "enclave/boot.sh",
            ],
        )

    def test_whole_context_copy_is_the_context_prefix(self):
        self.assertEqual(cd.dockerfile_copy_sources("COPY . /app/"), ["enclave/"])

    def test_real_dockerfile_sources_are_all_measured(self):
        with open(os.path.join(REPO, cd.DOCKERFILE)) as fh:
            sources = cd.dockerfile_copy_sources(fh.read())
        self.assertTrue(sources, "no COPY lines parsed from the real Dockerfile")
        for src in sources:
            with self.subTest(src=src):
                self.assertTrue(cd.is_measured(src), f"{src} is COPY'd but not in MEASURED")


class WorkflowFilters(unittest.TestCase):
    def test_parses_push_paths_block_only(self):
        text = """
on:
  push:
    branches: [main]
    paths:
      # a comment inside the list
      - 'enclave/src/**'
      - 'enclave/boot.sh'
      - "scripts/build-enclave.sh"
  workflow_dispatch:

jobs:
  build:
    steps:
      - name: not a path
"""
        self.assertEqual(
            cd.workflow_measured_filters(text),
            ["enclave/src/", "enclave/boot.sh", "scripts/build-enclave.sh"],
        )

    def test_real_workflow_filters_agree_with_measured(self):
        with open(os.path.join(REPO, cd.BUILD_WORKFLOW)) as fh:
            filters = cd.workflow_measured_filters(fh.read())
        self.assertTrue(filters)
        for entry in filters:
            with self.subTest(entry=entry):
                self.assertTrue(cd.is_measured(entry), f"{entry} triggers a build but is not in MEASURED")
        # And the other direction: everything MEASURED triggers a rebuild.
        for m in cd.MEASURED:
            with self.subTest(measured=m):
                self.assertIn(m, filters, f"{m} is MEASURED but would not trigger enclave-build.yml")


class SelfCheck(unittest.TestCase):
    def test_current_tree_has_no_gaps(self):
        os.chdir(REPO)
        self.assertEqual(cd.measured_paths_self_check(), [])

    def test_old_list_reports_the_reported_gaps(self):
        os.chdir(REPO)
        gaps = cd.measured_paths_self_check(measured=OLD_MEASURED)
        joined = "\n".join(gaps)
        for needle in ("enclave/attest/", "enclave/kmstool/", "scripts/build-enclave.sh"):
            with self.subTest(needle=needle):
                self.assertIn(needle, joined)

    def test_missing_dockerfile_is_a_gap_not_a_crash(self):
        gaps = cd.measured_paths_self_check(dockerfile="/nonexistent/Dockerfile")
        self.assertTrue(any("unreadable" in g for g in gaps))


if __name__ == "__main__":
    sys.exit(unittest.main())
