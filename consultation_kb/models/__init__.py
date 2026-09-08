"""Consultation domain model package.

Models are intentionally not eagerly imported: callers select the concrete
module so importing the lightweight entrypoint cannot load business runtime
dependencies before the Python-version gate.
"""
