# Open Exam Transparency Protocol (OETP): Vision Document

## The Problem

Indian entrance exams (NEET, JEE, CUET, state-level) lose billions in economic value and destroy millions of student futures annually due to systemic fraud.

**Human / organizational failures (~70% of incidents):**
- Paper leaks at source (strongroom breaches, insider translators/printers, coaching mafia)
- Impersonation via paid proxies
- OMR / answer sheet manipulation post-exam
- Grace mark abuse and normalization fraud
- Organized crime networks with political protection
- Whistleblower intimidation and suspicious deaths
- Zero accountability (2,000+ arrests in Vyapam, zero convictions)

**Structural / software failures (~30% of incidents):**
- A single plaintext paper for 2M+ candidates: one leak compromises everything
- No cryptographic chain of custody from question creation to result declaration
- Centralized single point of failure (one paper, one answer key, one target)
- Physical paper transport and storage
- No per-student encryption or variant isolation

## The Core Thesis

Most exam security focuses on *preventing* leaks, a losing battle against human nature. OETP takes a different approach: **make leaks economically worthless and make tampering mathematically detectable**.

If every student receives a unique encrypted exam packet, and if every packet is publicly committed before the exam, then:
- A leaked question bank cannot help a specific student without knowing their private variant assignment.
- A leaked physical or digital copy is useless because the content does not match any other student’s packet.
- Every answer submission is cryptographically bound to the exact packet the student saw.
- Any post-exam tampering with answers, answer keys, or results is detectable by independent observers.

## What OETP Covers and What It Does Not

**In scope:** secure delivery of per-student exam packets and cryptographic sealing of submissions, with public verification.

**Out of scope:** UI/UX, timers, biometrics, identity verification, in-exam proctoring, and preventing a student from photographing their own screen. OETP does not stop all cheating; it makes large-scale systemic fraud worthless.

## The Whole Process at a Glance

```
                    BEFORE EXAM
                    -----------

   Question Bank --► Generator --► 1 Unique Encrypted Packet Per Student
                                     │
                                     ▼
                           ┌----------------------┐
                           │ Public Merkle Root   │
                           │ + Ledger Anchor      │◄---- Courts, Media, RTI
                           │   "These packets     │       can all check it
                           │    are locked now"   │
                           └----------------------┘
                                     │
                    ┌----------------┼----------------┐
                    │                │                │
                    ▼                ▼                ▼
            Encrypted Packet   Key Envelope    Center Release Key
            (cached on PC)    (for that PC)    (for that center)


                    EXAM DAY (2 minutes before start)
                    ----------------------------------

   Local Beacon at Center --► Signs a Release Token --► Edge Daemon on each PC
        (authority rep)                                    validates it and
                                                            unlocks packets
                                                                     │
                    DURING EXAM                                      ▼
                    -----------                           Student sees their
                                                          unique paper via the
                                                          legacy exam UI
   Student answers --► Edge Daemon seals answers
                       │
                       ▼
            ┌----------------------┐
            │ Signed Receipt + QR  │----► Student keeps this (screenshot/print)
            │ Encrypted copy of    │
            │ my own answers       │
            └----------------------┘
                       │
                       ▼
            Signed hash forwarded to Ledger
            (or queued if offline)


                    AFTER EXAM
                    ----------

   Answer Key Hash --► Anchored to public ledger --► Results published
   (before results)         "This is the key
                            used for scoring"
```

## The Three-Part Architecture

### 1. Packet Generator
- Maintains a large question bank per tenant and exam.
- Generates a unique encrypted packet per student with stratified difficulty, variant values, and shuffled options.
- Publishes a Merkle commitment of all packet hashes **before the exam**, anchored to a government permissioned ledger.
- Publishes a signed final answer key **before result declaration**.

### 2. Edge Daemon
- A small, single-binary daemon installed on each testing machine.
- Caches per-student encrypted packets and key envelopes before the exam.
- Decrypts packets only at exam time, only after receiving a valid release token from a **per-center local beacon**.
- Serves plain questions to the legacy exam UI and returns a **signed, printable, QR-coded receipt** to every student after submission.
- Gives the student an encrypted personal copy of their own answers that only they can later open.
- Never stores plaintext on disk.

### 3. Ledger
- Maintains append-only Merkle trees per tenant.
- Anchors pre-exam, rolling, and final roots to a government permissioned ledger.
- Provides a **public verification portal** where any student can independently prove that their submission is recorded exactly as sealed.

## A Student’s Right to Verify

After submitting, every student receives a signed receipt containing:
- Their application number and unique student UUID
- The hash of the exact packet they were shown
- The hash of their submitted answers
- A timestamp
- A Merkle inclusion proof
- A QR code and a globally unique receipt ID

Using a public verification portal, the student can later prove:
1. Their packet was committed before the exam.
2. Their answers were sealed at submission time.
3. Their recorded answers are exactly what they submitted (via an encrypted personal copy they can unlock with their own credentials).
4. The final answer key used for scoring was committed before results were published.

This is the feature previous exam systems could not offer.

## Public Anchoring

Merkle roots are anchored to a government permissioned ledger so that independent parties (courts, RTI activists, coaching centers, parents, political opposition) can detect any retroactive rewrite of the ledger or answer key.

## Scale and Deployability

OETP is designed for India’s reality: low-cost, heterogeneous hardware, intermittent connectivity, and limited trust. It is built as a single static binary that runs on locked-down Linux images such as those already deployed by exam service providers. It does not require TPMs, secure enclaves, or high-end hardware. Targets include **2M submissions in a 10-minute window** and **50+ independent exam tenants** on one deployment.

## How Each Attack Is Contained or Detected

| Attack                                     | Defense                                                                                                                                   |
| ------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------- |
| **Paper leak at source**                   | Per-student random draw from a large bank; leaked questions do not match any specific student’s packet.                                   |
| **Question bank leak**                     | Without the per-student variant assignment and release token, the bank is economically worthless.                                         |
| **Answer substitution / result tampering** | Submission leaf binds `student_uuid + packet_hash + answers_hash`. Any movement or rewrite breaks the Merkle chain and the ledger anchor. |
| **Retroactive answer-key change**          | Answer key is anchored before results are published; any later change is detectable.                                                      |
| **Ledger manipulation by authority**       | Roots are anchored to a government permissioned ledger; rewritten roots do not match the anchored record.                                 |
| **Memory dumping on one machine**          | Compromise is contained to that machine; per-student keys are released just-in-time and zeroized after use.                               |
| **Network outage**                         | Encrypted packets and key envelopes are cached locally; signed submissions queue safely and flush when connectivity returns.              |
| **Release beacon bribery**                 | Each center has its own release key; a stolen key only unlocks that center’s exam window.                                                 |

## Out of Scope

- UI/UX, timers, student dashboards
- Identity verification / biometrics / proxy detection
- In-exam proctoring or screen-photography prevention
- Question authoring or content management
- Plain-text answer storage by legacy systems (OETP cannot control downstream systems)
