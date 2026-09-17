from __future__ import annotations  # noqa: D100


class CacheLabelFormatter:  # noqa: D101
    def format_ec2_inventory_collection_label(self, collection_name: str) -> str:  # noqa: D102
        labels = {
            "unused_elastic_ips": "unused Elastic IPs",
            "unattached_volumes": "unattached EBS volumes",
            "stopped_instances": "stopped EC2 instances",
            "nat_gateways": "NAT Gateways",
            "taggable_resources": "taggable EC2-family resources",
            "taggable_resources_without_nat_gateways": ("taggable EC2-family resources excluding NAT Gateways"),
            "running_instances": "running EC2 instances",
            "provisioned_iops_volumes": "provisioned IOPS EBS volumes",
        }
        return labels.get(collection_name, collection_name.replace("_", " "))


def format_ec2_inventory_collection_label(collection_name: str) -> str:  # noqa: D103
    return CacheLabelFormatter().format_ec2_inventory_collection_label(collection_name)
