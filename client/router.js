Router.configure({
  layoutTemplate: 'layout'
});

Router.map(function () {
  this.route('vfeed', {
    path: '/'
  });
});

//Router.route('/', function () {
//  this.render('Home');
//});
