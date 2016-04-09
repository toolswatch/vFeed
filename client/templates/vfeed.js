//vfeed Template helpers and events

Template.vfeed.rendered = function() {
    if(!this._rendered) {
      this._rendered = true;
    }
    sAlert.info("vFeed UI started", {effect: 'bouncyflip', position: 'top-right', timeout: 3000, onRouteClose: true, stack: true, offset: '100px'});
    Meteor.call('getStats', function(err, response){
      if(err){
        sAlert.error("vFeed stats could not be fetched, Try later!" + this._id, {effect: 'bouncyflip', position: 'top-right', timeout: 3000, onRouteClose: true, stack: true, offset: '100px'});

      }
      if(response){
        sAlert.success("vfeed Stats fetched", {effect: 'bouncyflip', position: 'top-right', timeout: 5000, onRouteClose: true, stack: true, offset: '100px'});
        Session.set("vfeed_stats", response);
      }

    });
}

Template.vfeed.helpers({
  vfeedStats : function(){
    return Session.get("vfeed_stats");
  }
});
