var Future = Npm.require("fibers/future");
var exec = Npm.require("child_process").exec;

Meteor.methods({
  'getStats': function() {
    // this.unblock();
    // var future = new Future();
    // //vfeedcli = process.env.PWD + '/vfeedcli.py';
    // //Spawn a child process for DoSCOSv2 Scan
    // var stats_command = "python ~/vFeed/vfeedcli.py --stats get_stats";
    // exec(stats_command, function(error, stdout, stderr){
    //     if(error){
    //         console.log(error);
    //     }
    //     future.return(stdout.toString());
    // });
    // return future.wait();
    return stat_vfeed_kpi.findOne({});
  }

})
