//! Local Detection Engine (LDE) for the Wazuh Desktop Agent.
//!
//! Evaluates detection rules locally at the edge — IOC matching via
//! Aho-Corasick + bloom filters, behavioral rule state machines, and
//! optional YARA file scanning — without a server round-trip.
