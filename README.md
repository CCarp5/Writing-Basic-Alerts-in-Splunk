# Writing-Basic-Alerts-in-Splunk

<h2>Description</h2>

In this walkthrough, we are going to build a simple Splunk detection for a successful brute-force attack using logs we generate from a simulated brute force attack.
<br />

If you would like to follow along with this walkthrough, I recommend following MyDFIR’s Active Directory Home Lab series on Youtube. I am using the same setup for this lab.
<br />

The first video in this series can be found [here](https://www.youtube.com/watch?v=5OessbOgyEo&list=PLG6KGSNK4PuBWmX9NykU0wnWamjxdKhDJ&index=13).


<br />


<h2>Utilities Used</h2>

- <b>Active Directory</b> 
- <b>Splunk</b>
- <b>Crowbar</b>


<h2>Simulating a brute force attack with Crowbar and checking for logs:</h2>

Before we begin, the use of Crowbar or any penetration testing tool should only be done in an environment that you own or have permission to be engaging in pentesting activity.
<br />

To begin we are going to run our simulated brute force attack.
<br />

To do this I’m using a wordlist that I have intentionally put 20 incorrect passwords on, followed by the correct password for one of my lab’s accounts.
<br />

This ensures that we will see a high quantity of failed logins prior to a successful login in a short amount of time, which is the type of activity we would like to build a detection for.

<br />

![ ](https://github.com/CCarp5/Writing-Basic-Alerts-in-Splunk/blob/main/1RunningCrowbar.png)

<br />
Here we can see that crowbar was able to successfully sign in to an account, which means our next step is to go look at the logs from this successful login as well as the previous failed attempts.
<br />

To do this we will pivot to Splunk.
<br />

Because we know we recently performed this activity, we can go ahead and set our search time to something recent, in this case 15 minutes and we’ll run a search for all logs from the device we targeted, in this case “TARGET-PC”.
<br />

Note: In this setup I only have one index running in Splunk, “endpoint”

<br />

![ ](https://github.com/CCarp5/Writing-Basic-Alerts-in-Splunk/blob/main/2FirstSearch.png)

<br />
<br />

We can see that even though we have narrowed down our search to a single device and small time period, we still quite a few events to sort through. In order to make this easier we are going to narrow down our search even further by looking for events relevant to the logs we are trying to review. 
<br />

In a production environment or in a situation where you’re attempting to gather logs from an event to write detections catered to that event, this stage would be more difficult and time intensive, however because we are in a testing environment looking for logs we generated, we can cater our search to only show the logs we are looking for.
<br />

We’ll do that by adding the following to our search:

"EventCode=4624" OR "EventCode=4625" jsmith

This narrows down our search to only show logs for the user jsmith that contain the Event Codes 4624 and 4625.

_If you are unfamiliar with these event codes, I strongly recommend you search them [here](https://www.ultimatewindowssecurity.com/) at Ultimate Windows Security_
<br />

Now we will review one of these events in depth by clicking “show all XX(number will vary) lines” to review for fields that we may want to see when investigating a brute-force alert.

<br />

![ ](https://github.com/CCarp5/Writing-Basic-Alerts-in-Splunk/blob/main/3ReviewingLogs.png)

<br />
<br />

Looking through these fields we can and thinking about what would be relevant, we are going to make note of the following fields
<br />

Account Name
<br />

Source Network Address
<br />

Failure Reason
<br />

It’s important to keep in mind how these fields are labeled in the event log. If we build our search using terms like “user name” instead of Account Name or “IP Address” instead of Source Network Address, our detection will not pick up on these logs.
<br />

<h2>Writing the search for our detection:</h2>


Now that we know what fields we want to base our detection off of, we’re ready to begin writing the detection.
<br />

We’ll start by setting our index to where are logs are present and filtering our search for only Event Codes 4624 and 4625, this will make our search more by only searching for logs relevant to our desired detection.

<br />

![ ](https://github.com/CCarp5/Writing-Basic-Alerts-in-Splunk/blob/main/4PointingSearch.png)

<br />
<br />

Now we’ll want to extract account names, login failures, timestamps, and failure reasons.
<br />

We’ll do this by adding the following to our search:
<br />

| stats count earliest(_time) as first_attempt latest(_time) as last_attempt values(Source_Network_Address) as Source_IP values(Failure_Reason) by Account_Name, EventCode

<br />

![ ](https://github.com/CCarp5/Writing-Basic-Alerts-in-Splunk/blob/main/5BuildingSearch.png)

<br />
<br />

This portion of our search does quite a bit, so we're going to break it down individually.
<br />
•	stats count → Counts the total number of login attempts per user (Account_Name).
<br />
•	earliest(_time) as first_attempt → Captures the first recorded failed attempt.
<br />
•	latest(_time) as last_attempt → Captures the last failed attempt.
<br />
•	values(Source_Network_Address) as Source_IP → Stores all unique IPs used in the attempts, and translates the field in our results to "Source IPs" for clarity when investigating.
<br />
•	values(Failure_Reason) → Collects all failure reasons (e.g., "Unknown username or bad password", "Account locked out").
<br />
•	by Account_Name, EventCode → Groups results separately for failed (4625) and successful (4624) logins.

<br />
<br />
Now we’ll want to only show logins with above a certain amount of login failures, for this case we’ll set the threshold to 15. We’ll do this by adding to our search:
<br />

| where EventCode=4625 AND count >= 15

<br />

![ ](https://github.com/CCarp5/Writing-Basic-Alerts-in-Splunk/blob/main/6FilteringJustHighFailures.png)

<br />
<br />

Now we are showing users with 15 or more failed login attempts, along with (currently unreadable) timestamps of the first and last attempt, as well as the source IP of the attempts and the reason for failure
<br />

Now we must join this search that is only going to show failed login attempts with another search that will look for successful login attempts. With future investigations in mind we also want to incorporate a timestamp for the successful login. We’ll do this by adding the following section to our search:
<br />

| join type=inner Account_Name [
    search index=endpoint EventCode=4624
    | stats earliest(_time) as success_time by Account_Name
]

<br />

![ ](https://github.com/CCarp5/Writing-Basic-Alerts-in-Splunk/blob/main/7UsingtheJoinFunction.png)

<br />
<br />

There is a lot going on in this portion of the search, so we're going to break it down individually.
<br />
•	join type=inner runs a subsearch to look for 4624 (successful logins).
<br />
•	stats earliest(_time) as success_time by Account_Name → Finds the first successful login per user.
<br />
•	join type=inner Account_Name → Merges failed attempts (4625) with successful logins (4624) using Account_Name as the common field.
<br />
•	Keeps only users who had both failed and successful logins.
<br />

This is how we differentiate our detection for a **sucessful** brute-force attempt from a detection for any brute force attempt that will just monitor for a high volume of failed logins by a single user.

<br />
<br />

Now we will address our unreadable timestamps, to do this we must use the strftime function. This takes our timestamps, currently in epoch format, and converts them to human readable timestamps. We will do this for each of our timestamp fields by adding the following section to our search:
<br />

| eval first_attempt = strftime(first_attempt, "%Y-%m-%d %H:%M:%S")
<br />
| eval last_attempt = strftime(last_attempt, "%Y-%m-%d %H:%M:%S")
<br />
| eval success_time = strftime(success_time, "%Y-%m-%d %H:%M:%S")

<br />

![ ](https://github.com/CCarp5/Writing-Basic-Alerts-in-Splunk/blob/main/8MakingTimestampsReadable.png)

<br />
<br />

Our timestamps are now in a readable format.
<br />

Now the purpose of our alert is to trigger when a successful login attempt is observed quickly after a series of failed login attempts. In this case “quickly” will be 5 minutes after the latest attempt.
<br />

We will accomplish this by converting our timestamps back to the epoch format using the strptime function, so that the value for the last failed attempt and the successful sign in can be subtracted from each other. The difference between the two values will be interpreted by Splunk in seconds, so to achieve our desired outcome of alerting upon successful logins 5 minutes after a brute-force attempt we want to set the threshold to be under 300. We will accomplish this by adding the following line to our search:
<br />

| where strptime(success_time, "%Y-%m-%d %H:%M:%S") - strptime(last_attempt, "%Y-%m-%d %H:%M:%S") <= 300

<br />

![ ](https://github.com/CCarp5/Writing-Basic-Alerts-in-Splunk/blob/main/9IsolatingTimeFrame.png)

<br />
<br />

Because we are in a lab environment where we have created the perfect scenario to trigger our alert, our results haven’t changed. However before this addition, if a user had 15 failed logins over the course of a week, then a successful login, an alert would have triggered which would not be indicative of brute force activity.
<br />

Now we will clean up our search. From looking at the results I see 2 issues, we are receiving results for the user “-“ identical to our actual user jsmith. This is likely due to logs generated by our Domain Controller that is observing the logins not parsing username correctly. Because the timestamps are identical, we can safely assume that this is a duplicate and okay to be tuned out and not going to result in false negatives, we’ll do that by adding the following to our search:
<br />
| where Account_Name!="-"

<br />

![ ](https://github.com/CCarp5/Writing-Basic-Alerts-in-Splunk/blob/main/10TuningNullUser.png)

<br />
<br />

Now we can see that we are just seeing results with a legitimate user.
<br />

The second, albeit minor, issue we can see is where our results field lists the Failure Reason field as “values(Failure_Reason)” to simplify our results field and for consistency purposes we will rename this field by adding the following to the end of our search:
<br />

| rename values(Failure_Reason) as Failure_Reason

<br />

![ ](https://github.com/CCarp5/Writing-Basic-Alerts-in-Splunk/blob/main/11CleaningUpSearch.png)

<br />
<br />

Now we can see our search listing all desired fields as intended. Now that our search is built, we must save this and make the appropriate configurations for our alert to trigger as intended. We’ll start by clicking “Save As” in the top right corner then selecting “Alert”.

<br />

![ ](https://github.com/CCarp5/Writing-Basic-Alerts-in-Splunk/blob/main/12TriggerSettings.png)

<br />
<br />

Now we will configure the settings for our alert. Our name will be simple and descriptive, as well as our description. 
<br />

We will also set our permissions to shared in app because in most environments, you won’t be writing alerts just for yourself. 
<br />

We will also set the alert type to “Real Time” to ensure we are alerted on this activity as it happens. 
<br />

For trigger conditions we will select “Per-Result” because our search is built to only generate an alert after the successful login is observed. 
<br />

Under “Trigger Actions” we will select “Add to Triggered Alerts”
<br />

Splunk has multiple options for Trigger Actions, including sending an email or running a script. For our use case, we will just add an entry to triggered alerts.
<br />

Splunk also offers 5 severity options: Info, Low, Medium, High, and Critical. Other than a minor graphical change in the triggered alerts section, these severities make no changes to how Splunk handles the alert.
<br />

Now we will press save and move on to testing.
<br />

<h2>Simulating another brute force attack to test our alert:</h2>


We will test the same way we generated logs, by conducting another brute force attack using crowbar.

<br />

![ ](https://github.com/CCarp5/Writing-Basic-Alerts-in-Splunk/blob/main/13RunningCrowbar.png)

<br />
<br />

Now that we have successfully simulated another brute force attack, we will look to see if we have generated an alert in Splunk under “Activity” and “Triggered Alerts”.

<br />

![ ](https://github.com/CCarp5/Writing-Basic-Alerts-in-Splunk/blob/main/14ViewingOurTriggeredAlert.png)

<br />
<br />

We can see that our alert has triggered as intended. To see the details of the alert we’ve triggered we will select “View Results”

<br />

![ ](https://github.com/CCarp5/Writing-Basic-Alerts-in-Splunk/blob/main/15ReviewingtheAlert.png)

<br />
<br />

We can see our search showing all intended fields and providing relevant information for investigation.

<br />
<br />

This detection is simple but provides information that would be relative to an investigation.
<br />

If you'd like to expand on this walkthrough you could make this detection even more effective by doing any of the following:
<br />
•	Using Splunk's coalesce() function to ensure field consistency across different log sources.
<br />
•	Creating different versions of the detection with different thresholds tied to different severity levels.
<br />
•	Parsing the login service to create similar alerts for specific protocols such as RDP.
<br />

Thank you for following along with this walkthrough!


<!--
 ```diff
- text in red
+ text in green
! text in orange
# text in gray
@@ text in purple (and bold)@@
```
--!>
