package main

import (
	"bufio"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/convox/cli/Godeps/_workspace/src/github.com/aws/aws-sdk-go/aws"
	"github.com/convox/cli/Godeps/_workspace/src/github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/convox/cli/Godeps/_workspace/src/github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/convox/cli/Godeps/_workspace/src/github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/convox/cli/Godeps/_workspace/src/github.com/aws/aws-sdk-go/service/lambda"
	"github.com/convox/cli/Godeps/_workspace/src/github.com/aws/aws-sdk-go/service/sns"
	"github.com/convox/cli/Godeps/_workspace/src/github.com/codegangsta/cli"
	"github.com/convox/cli/stdcli"
)

// https://docs.aws.amazon.com/general/latest/gr/rande.html#lambda_region
var lambdaRegions = map[string]bool{"us-east-1": true, "us-west-2": true, "eu-west-1": true, "ap-northeast-1": true}

// https://docs.aws.amazon.com/general/latest/gr/rande.html#ecs_region
var ecsRegions = map[string]bool{"us-east-1": true, "us-west-1": false, "us-west-2": true, "eu-west-1": true, "ap-northeast-1": true, "ap-southeast-2": true}

func init() {
	rand.Seed(time.Now().UTC().UnixNano())

	stdcli.RegisterCommand(cli.Command{
		Name:        "install",
		Description: "install convox into an aws account",
		Usage:       "",
		Action:      cmdInstall,
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "dedicated",
				Usage: "create EC2 instances on dedicated hardware",
			},
			cli.IntFlag{
				Name:  "instance-count",
				Value: 3,
				Usage: "number of EC2 instances",
			},
			cli.StringFlag{
				Name:  "instance-type",
				Value: "t2.small",
				Usage: "type of EC2 instances",
			},
			cli.StringFlag{
				Name:   "region",
				Value:  "us-east-1",
				Usage:  "aws region to install in",
				EnvVar: "AWS_REGION",
			},
			cli.StringFlag{
				Name:   "stack-name",
				EnvVar: "STACK_NAME",
				Value:  "convox",
				Usage:  "name of the CloudFormation stack",
			},
			cli.BoolFlag{
				Name:   "development",
				EnvVar: "DEVELOPMENT",
				Usage:  "create additional CloudFormation outputs to copy development .env file",
			},
			cli.StringFlag{
				Name:  "key",
				Usage: "name of an SSH keypair to install on EC2 instances",
			},
			cli.StringFlag{
				Name:   "version",
				EnvVar: "VERSION",
				Value:  "latest",
				Usage:  "release version in the format of '20150810161818', or 'latest' by default",
			},
		},
	})

	stdcli.RegisterCommand(cli.Command{
		Name:        "uninstall",
		Description: "uninstall convox from an aws account",
		Usage:       "",
		Action:      cmdUninstall,
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "force",
				Usage: "uninstall even if apps exist",
			},
			cli.StringFlag{
				Name:   "region",
				Value:  "us-east-1",
				Usage:  "aws region to uninstall from",
				EnvVar: "AWS_REGION",
			},
			cli.StringFlag{
				Name:   "stack-name",
				EnvVar: "STACK_NAME",
				Value:  "convox",
				Usage:  "name of the convox stack",
			},
		},
	})
}

func cmdInstall(c *cli.Context) {
	region := c.String("region")
	lambdaRegion := region

	if !ecsRegions[region] {
		stdcli.Error(fmt.Errorf("Convox is not currently supported in %s", region))
	}

	tenancy := "default"
	instanceType := c.String("instance-type")

	if c.Bool("dedicated") {
		tenancy = "dedicated"
		if strings.HasPrefix(instanceType, "t2") {
			stdcli.Error(fmt.Errorf("t2 instance types aren't supported in dedicated tenancy, please set --instance-type."))
		}
	}

	fmt.Println(`

     ___    ___     ___   __  __    ___   __  _
    / ___\ / __ \ /  _  \/\ \/\ \  / __ \/\ \/ \
   /\ \__//\ \_\ \/\ \/\ \ \ \_/ |/\ \_\ \/>  </
   \ \____\ \____/\ \_\ \_\ \___/ \ \____//\_/\_\
    \/____/\/___/  \/_/\/_/\/__/   \/___/ \//\/_/

 `)

	fmt.Println("This installer needs AWS credentials to install the Convox platform into")
	fmt.Println("your AWS account. These credentials will only be used to communicate")
	fmt.Println("between this installer running on your computer and the AWS API.")
	fmt.Println("")
	fmt.Println("We recommend that you create a new set of credentials exclusively for this")
	fmt.Println("install process and then delete them once the installer has completed.")
	fmt.Println("")
	fmt.Println("To generate a new set of AWS credentials go to:")
	fmt.Println("https://docs.convox.com/docs/creating-an-iam-user-and-credentials")
	fmt.Println("")

	distinctId, err := currentId()

	if err != nil {
		handleError("install", distinctId, err)
		return
	}

	reader := bufio.NewReader(os.Stdin)

	access := os.Getenv("AWS_ACCESS_KEY_ID")
	secret := os.Getenv("AWS_SECRET_ACCESS_KEY")

	if access == "" || secret == "" {
		var err error

		fmt.Print("AWS Access Key ID: ")

		access, err = reader.ReadString('\n')

		if err != nil {
			stdcli.Error(err)
		}

		fmt.Print("AWS Secret Access Key: ")

		secret, err = reader.ReadString('\n')

		if err != nil {
			stdcli.Error(err)
		}

		fmt.Println("")
	}

	development := "No"
	if c.Bool("development") {
		development = "Yes"
	}

	key := c.String("key")

	stackName := c.String("stack-name")

	version := c.String("version")
	if version == "" {
		version = "latest"
	}

	var BootstrapUrl = fmt.Sprintf("http://convox.s3.amazonaws.com/release/%s/bootstrap.json", version)
	var FormationUrl = fmt.Sprintf("http://convox.s3.amazonaws.com/release/%s/formation.json", version)

	instanceCount := fmt.Sprintf("%d", c.Int("instance-count"))

	access = strings.TrimSpace(access)
	secret = strings.TrimSpace(secret)

	fmt.Println("Installing Convox...")

	externalCustomTopic := ""
	if !lambdaRegions[region] {
		lambdaRegion = "us-east-1"
		fmt.Printf("Lambda is not supported in %s, creating bootstrap in %s:\n", region, lambdaRegion)

		SNS := sns.New(&aws.Config{
			Region:      region,
			Credentials: credentials.NewStaticCredentials(access, secret, ""),
		})

		snsResp, err := SNS.CreateTopic(&sns.CreateTopicInput{
			Name: aws.String(stackName + "-bootstrap"),
		})

		if err != nil {
			handleError("install", distinctId, err)
			return
		}
		externalCustomTopic = *snsResp.TopicARN

		BootstrapCloudFormation := cloudformation.New(&aws.Config{
			Region:      lambdaRegion,
			Credentials: credentials.NewStaticCredentials(access, secret, ""),
		})

		bres, err := BootstrapCloudFormation.CreateStack(&cloudformation.CreateStackInput{
			Capabilities: []*string{aws.String("CAPABILITY_IAM")},
			Parameters: []*cloudformation.Parameter{
				&cloudformation.Parameter{ParameterKey: aws.String("Version"), ParameterValue: aws.String(version)},
			},
			StackName:   aws.String(stackName + "-bootstrap"),
			TemplateURL: aws.String(BootstrapUrl),
		})

		if err != nil {
			handleError("install", distinctId, err)
			return
		}

		bootstrap, err := waitForCompletion(*bres.StackID, BootstrapCloudFormation, false)

		if err != nil {
			handleError("install", distinctId, err)
			return
		}

		Lambda := lambda.New(&aws.Config{
			Region:      lambdaRegion,
			Credentials: credentials.NewStaticCredentials(access, secret, ""),
		})

		_, err = Lambda.AddPermission(&lambda.AddPermissionInput{
			Action:       aws.String("lambda:invokeFunction"),
			FunctionName: aws.String(bootstrap),
			StatementID:  aws.String("StatementID"),
			Principal:    aws.String("sns.amazonaws.com"),
			SourceARN:    aws.String(externalCustomTopic),
		})

		if err != nil {
			handleError("install", distinctId, err)
			return
		}

		_, err = SNS.Subscribe(&sns.SubscribeInput{
			Protocol: aws.String("lambda"),
			TopicARN: aws.String(externalCustomTopic),
			Endpoint: aws.String(bootstrap),
		})

		if err != nil {
			handleError("install", distinctId, err)
			return
		}
		fmt.Println("Continuing normal install...")
	}

	password := randomString(30)

	CloudFormation := cloudformation.New(&aws.Config{
		Region:      region,
		Credentials: credentials.NewStaticCredentials(access, secret, ""),
	})

	stackInput := &cloudformation.CreateStackInput{
		Capabilities: []*string{aws.String("CAPABILITY_IAM")},
		Parameters: []*cloudformation.Parameter{
			&cloudformation.Parameter{ParameterKey: aws.String("ClientId"), ParameterValue: aws.String(distinctId)},
			&cloudformation.Parameter{ParameterKey: aws.String("Development"), ParameterValue: aws.String(development)},
			&cloudformation.Parameter{ParameterKey: aws.String("InstanceCount"), ParameterValue: aws.String(instanceCount)},
			&cloudformation.Parameter{ParameterKey: aws.String("InstanceType"), ParameterValue: aws.String(instanceType)},
			&cloudformation.Parameter{ParameterKey: aws.String("Key"), ParameterValue: aws.String(key)},
			&cloudformation.Parameter{ParameterKey: aws.String("Password"), ParameterValue: aws.String(password)},
			&cloudformation.Parameter{ParameterKey: aws.String("Tenancy"), ParameterValue: aws.String(tenancy)},
			&cloudformation.Parameter{ParameterKey: aws.String("Version"), ParameterValue: aws.String(version)},
		},
		StackName:   aws.String(stackName),
		TemplateURL: aws.String(FormationUrl),
	}

	if externalCustomTopic != "" {
		stackInput.Parameters = append(stackInput.Parameters, &cloudformation.Parameter{ParameterKey: aws.String("ExternalCustomTopic"), ParameterValue: aws.String(externalCustomTopic)})
	}

	res, err := CloudFormation.CreateStack(stackInput)

	if err != nil {
		sendMixpanelEvent(fmt.Sprintf("convox-install-error"), err.Error())

		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == "AlreadyExistsException" {
				stdcli.Error(fmt.Errorf("Stack %q already exists. Run `convox uninstall` then try again.", stackName))
			}
		}

		stdcli.Error(err)
	}

	sendMixpanelEvent("convox-install-start", "")

	host, err := waitForCompletion(*res.StackID, CloudFormation, false)

	if err != nil {
		handleError("install", distinctId, err)
		return
	}

	fmt.Println("Waiting for load balancer...")

	waitForAvailability(fmt.Sprintf("http://%s/", host))

	fmt.Println("Logging in...")

	addLogin(host, password)
	switchHost(host)

	fmt.Println("Success, try `convox apps`")

	sendMixpanelEvent("convox-install-success", "")
}

func cmdUninstall(c *cli.Context) {
	if !c.Bool("force") {
		apps := getApps()

		if len(*apps) != 0 {
			stdcli.Error(fmt.Errorf("Please delete all apps before uninstalling."))
		}
	}

	fmt.Println(`

     ___    ___     ___   __  __    ___   __  _
    /'___\ / __'\ /' _ '\/\ \/\ \  / __'\/\ \/'\
   /\ \__//\ \_\ \/\ \/\ \ \ \_/ |/\ \_\ \/>  </
   \ \____\ \____/\ \_\ \_\ \___/ \ \____//\_/\_\
    \/____/\/___/  \/_/\/_/\/__/   \/___/ \//\/_/

 `)

	fmt.Println("This uninstaller needs AWS credentials to uninstall the Convox platform from")
	fmt.Println("your AWS account. These credentials will only be used to communicate")
	fmt.Println("between this uninstaller running on your computer and the AWS API.")
	fmt.Println("")
	fmt.Println("We recommend that you create a new set of credentials exclusively for this")
	fmt.Println("uninstall process and then delete them once the uninstaller has completed.")
	fmt.Println("")
	fmt.Println("To generate a new set of AWS credentials go to:")
	fmt.Println("https://docs.convox.com/docs/creating-an-iam-user-and-credentials")
	fmt.Println("")

	reader := bufio.NewReader(os.Stdin)

	access := os.Getenv("AWS_ACCESS_KEY_ID")
	secret := os.Getenv("AWS_SECRET_ACCESS_KEY")
	region := c.String("region")

	if access == "" || secret == "" {
		var err error

		fmt.Print("AWS Access Key: ")

		access, err = reader.ReadString('\n')

		if err != nil {
			stdcli.Error(err)
		}

		fmt.Print("AWS Secret Access Key: ")

		secret, err = reader.ReadString('\n')

		if err != nil {
			stdcli.Error(err)
		}
	}

	stackName := c.String("stack-name")

	fmt.Println("")

	fmt.Println("Uninstalling Convox...")

	distinctId := randomString(10)

	access = strings.TrimSpace(access)
	secret = strings.TrimSpace(secret)

	CloudFormation := cloudformation.New(&aws.Config{
		Region:      region,
		Credentials: credentials.NewStaticCredentials(access, secret, ""),
	})

	res, err := CloudFormation.DescribeStacks(&cloudformation.DescribeStacksInput{
		StackName: aws.String(stackName),
	})

	if err != nil {
		sendMixpanelEvent(fmt.Sprintf("convox-uninstall-error"), err.Error())

		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == "ValidationError" {
				stdcli.Error(fmt.Errorf("Stack %q does not exist.", stackName))
			}
		}

		stdcli.Error(err)
	}

	stackId := *res.Stacks[0].StackID

	_, err = CloudFormation.DeleteStack(&cloudformation.DeleteStackInput{
		StackName: aws.String(stackId),
	})

	if err != nil {
		handleError("uninstall", distinctId, err)
		return
	}

	sendMixpanelEvent("convox-uninstall-start", "")

	_, err = waitForCompletion(stackId, CloudFormation, true)

	if err != nil {
		handleError("uninstall", distinctId, err)
		return
	}

	host := ""
	for _, o := range res.Stacks[0].Outputs {
		if *o.OutputKey == "Dashboard" {
			host = *o.OutputValue
			break
		}
	}

	if configuredHost, _ := currentHost(); configuredHost == host {
		removeHost()
	}
	removeLogin(host)

	fmt.Println("Successfully uninstalled.")

	sendMixpanelEvent("convox-uninstall-success", "")
}

func waitForCompletion(stack string, CloudFormation *cloudformation.CloudFormation, isDeleting bool) (string, error) {
	for {
		dres, err := CloudFormation.DescribeStacks(&cloudformation.DescribeStacksInput{
			StackName: aws.String(stack),
		})

		if err != nil {
			stdcli.Error(err)
		}

		err = displayProgress(stack, CloudFormation, isDeleting)

		if err != nil {
			stdcli.Error(err)
		}

		if len(dres.Stacks) != 1 {
			stdcli.Error(fmt.Errorf("could not read stack status"))
		}

		switch *dres.Stacks[0].StackStatus {
		case "CREATE_COMPLETE":
			// Dump .env if DEVELOPMENT
			development := os.Getenv("DEVELOPMENT")

			if development == "Yes" {
				fmt.Printf("Development .env:\n")

				// convert Port5432TcpAddr to PORT_5432_TCP_ADDR
				re := regexp.MustCompile("([a-z])([A-Z0-9])") // lower case letter followed by upper case or number, i.e. Port5432
				re2 := regexp.MustCompile("([0-9])([A-Z])")   // number followed by upper case letter, i.e. 5432Tcp

				for _, o := range dres.Stacks[0].Outputs {
					k := re.ReplaceAllString(*o.OutputKey, "${1}_${2}")
					k = re2.ReplaceAllString(k, "${1}_${2}")
					k = strings.ToUpper(k)

					fmt.Printf("%v=%v\n", k, *o.OutputValue)
				}
			}

			for _, o := range dres.Stacks[0].Outputs {
				if *o.OutputKey == "Dashboard" || *o.OutputKey == "Bootstrap" {
					return *o.OutputValue, nil
				}
			}

			return "", fmt.Errorf("could not install stack, contact support@convox.com for assistance")
		case "CREATE_FAILED":
			return "", fmt.Errorf("stack creation failed, contact support@convox.com for assistance")
		case "ROLLBACK_COMPLETE":
			return "", fmt.Errorf("stack creation failed, contact support@convox.com for assistance")
		case "DELETE_COMPLETE":
			return "", nil
		case "DELETE_FAILED":
			return "", fmt.Errorf("stack deletion failed, contact support@convox.com for assistance")
		}

		time.Sleep(2 * time.Second)
	}
}

var events = map[string]bool{}

func displayProgress(stack string, CloudFormation *cloudformation.CloudFormation, isDeleting bool) error {
	res, err := CloudFormation.DescribeStackEvents(&cloudformation.DescribeStackEventsInput{
		StackName: aws.String(stack),
	})

	if err != nil {
		return err
	}

	for _, event := range res.StackEvents {
		if events[*event.EventID] == true {
			continue
		}

		events[*event.EventID] = true

		// Log all CREATE_FAILED to display and MixPanel
		if !isDeleting && *event.ResourceStatus == "CREATE_FAILED" {
			msg := fmt.Sprintf("Failed %s: %s", *event.ResourceType, *event.ResourceStatusReason)
			fmt.Println(msg)
			sendMixpanelEvent("convox-install-error", msg)
		}

		name := friendlyName(*event.ResourceType)

		if name == "" {
			continue
		}

		switch *event.ResourceStatus {
		case "CREATE_IN_PROGRESS":
		case "CREATE_COMPLETE":
			if !isDeleting {
				id := *event.PhysicalResourceID

				if strings.HasPrefix(id, "arn:") {
					id = *event.LogicalResourceID
				}

				fmt.Printf("Created %s: %s\n", name, id)
			}
		case "CREATE_FAILED":
		case "DELETE_IN_PROGRESS":
		case "DELETE_COMPLETE":
			id := *event.PhysicalResourceID

			if strings.HasPrefix(id, "arn:") {
				id = *event.LogicalResourceID
			}

			fmt.Printf("Deleted %s: %s\n", name, id)
		case "DELETE_SKIPPED":
			id := *event.PhysicalResourceID

			if strings.HasPrefix(id, "arn:") {
				id = *event.LogicalResourceID
			}

			fmt.Printf("Skipped %s: %s\n", name, id)
		case "DELETE_FAILED":
			return fmt.Errorf("stack deletion failed")
		case "ROLLBACK_IN_PROGRESS", "ROLLBACK_COMPLETE":
		case "UPDATE_IN_PROGRESS", "UPDATE_COMPLETE", "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS", "UPDATE_FAILED", "UPDATE_ROLLBACK_IN_PROGRESS", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED":
		default:
			return fmt.Errorf("Unhandled status: %s\n", *event.ResourceStatus)
		}
	}

	return nil
}

func friendlyName(t string) string {
	switch t {
	case "AWS::AutoScaling::AutoScalingGroup":
		return "AutoScalingGroup"
	case "AWS::AutoScaling::LaunchConfiguration":
		return ""
	case "AWS::CloudFormation::Stack":
		return "CloudFormation Stack"
	case "AWS::EC2::InternetGateway":
		return "VPC Internet Gateway"
	case "AWS::EC2::Route":
		return ""
	case "AWS::EC2::RouteTable":
		return "Routing Table"
	case "AWS::EC2::SecurityGroup":
		return "Security Group"
	case "Custom::EC2Subnets":
		return "VPC Subnet"
	case "Custom::EC2SubnetRouteTableAssociation":
		return ""
	case "AWS::EC2::VPC":
		return "VPC"
	case "AWS::EC2::VPCGatewayAttachment":
		return ""
	case "AWS::ECS::Cluster":
		return "ECS Cluster"
	case "AWS::ElasticLoadBalancing::LoadBalancer":
		return "Elastic Load Balancer"
	case "AWS::Lambda::Function":
		return "Lambda Function"
	case "AWS::IAM::AccessKey":
		return "Access Key"
	case "AWS::IAM::InstanceProfile":
		return ""
	case "AWS::IAM::Role":
		return ""
	case "AWS::IAM::User":
		return "IAM User"
	case "AWS::Kinesis::Stream":
		return "Kinesis Stream"
	case "AWS::S3::Bucket":
		return "S3 Bucket"
	case "AWS::DynamoDB::Table":
		return "DynamoDB Table"
	case "Custom::EC2AvailabilityZones":
		return ""
	case "Custom::ECSTaskDefinition":
		return "ECS TaskDefinition"
	case "Custom::ECSService":
		return "ECS Service"
	case "Custom::S3BucketCleanup":
		return ""
	}

	return fmt.Sprintf("Unknown: %s", t)
}

func waitForAvailability(url string) {
	client := &http.Client{
		Timeout: 2 * time.Second,
	}

	for {
		_, err := client.Get(url)

		if err == nil {
			return
		}
	}
}

func handleError(command string, distinctId string, err error) {
	sendMixpanelEvent(fmt.Sprintf("convox-%s-error", command), err.Error())
	stdcli.Error(err)
}

var randomAlphabet = []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")

func randomString(size int) string {
	b := make([]rune, size)
	for i := range b {
		b[i] = randomAlphabet[rand.Intn(len(randomAlphabet))]
	}
	return string(b)
}
