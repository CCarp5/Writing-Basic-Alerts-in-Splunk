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

To begin we are going to run our simulated brute force attack.
<br />

To do this I’m using a wordlist that I have intentionally put 20 incorrect passwords on, followed by the correct password for one of my lab’s accounts.
<br />

This ensures that we will see a high quantity of failed logins prior to a successful login in a short amount of time, which is the type of activity we would like to build a detection for.

<br />

<br />
<br />

Here we can see that crowbar was able to successfully sign in to an account, which means our next step is to go look at the logs from this successful login as well as the previous failed attempts.
<br />
![ ](main/1RunningCrowbar.png)
<br />
<br />
To do this we will pivot to Splunk.
<br />

Because we know we recently performed this activity, we can go ahead and set our search time to something recent, in this case 15 minutes and we’ll run a search for all logs from the device we targeted, in this case “TARGET-PC”.
<br />

Note: In this setup I only have one index running in Splunk, “endpoint”

<br />
<br />
<br />




<!--
 ```diff
- text in red
+ text in green
! text in orange
# text in gray
@@ text in purple (and bold)@@
```
--!>
