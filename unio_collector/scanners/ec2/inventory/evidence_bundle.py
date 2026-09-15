from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.ebs.volume_record import EbsVolumeRecord
    from unio_collector.aws.ec2.elastic_ip_record import ElasticIpRecord
    from unio_collector.aws.ec2.stopped_instance_record import StoppedInstanceRecord
    from unio_collector.aws.network.nat_gateway_record import NatGatewayRecord


@dataclass(frozen=True)
class Ec2InventoryEvidenceBundle:  # noqa: D101
    elastic_ips: list[ElasticIpRecord] = field(default_factory=list)
    ebs_volumes: list[EbsVolumeRecord] = field(default_factory=list)
    stopped_instances: list[StoppedInstanceRecord] = field(default_factory=list)
    nat_gateways: list[NatGatewayRecord] = field(default_factory=list)
    regions: list[str] = field(default_factory=list)
