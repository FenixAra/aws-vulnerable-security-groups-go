package main

import (
	"log"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
)

func main() {
	svc := ec2.New(session.New())
	var maxResults int64
	maxResults = 500
	var nextToken string
	for {
		descSGInput := &ec2.DescribeSecurityGroupsInput{
			MaxResults: aws.Int64(maxResults),
		}

		if nextToken != "" {
			descSGInput.NextToken = aws.String(nextToken)
		}

		descSGOut, err := svc.DescribeSecurityGroups(descSGInput)
		if err != nil {
			log.Println("Unable to get security groups. Err:", err)
			os.Exit(1)
		}

		for _, sg := range descSGOut.SecurityGroups {
			for _, ingress := range sg.IpPermissions {
				if (ingress.FromPort != nil && *ingress.FromPort == 80 && *ingress.ToPort == 80) ||
					(ingress.ToPort != nil && *ingress.FromPort == 443 && *ingress.ToPort == 443) {
					continue
				}

				if len(ingress.IpRanges) > 0 {
					for _, ipRange := range ingress.IpRanges {
						if *ipRange.CidrIp == "0.0.0.0/0" {
							var fromPort, toPort int64
							if ingress.FromPort != nil {
								fromPort = *ingress.FromPort
							}

							if ingress.ToPort != nil {
								toPort = *ingress.ToPort
							}

							log.Printf(`Unsafe security group. ID: %s, Name: %s, FromPort: %d, ToPort: %d`,
								*sg.GroupId, *sg.GroupName,
								fromPort, toPort)
						}
					}
				}
			}
		}

		if descSGOut.NextToken != nil {
			nextToken = *descSGOut.NextToken
		} else {
			break
		}
	}
}
